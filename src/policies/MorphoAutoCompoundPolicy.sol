// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {AutoCompoundPeriphery} from "../AutoCompoundPeriphery.sol";
import {IMerklDistributor} from "../interfaces/merkl/IMerklDistributor.sol";
import {IMorphoVault} from "../interfaces/morpho/IMorphoVault.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";
import {SingleExecutorAuthorizedPolicy} from "./SingleExecutorAuthorizedPolicy.sol";

/// @title MorphoAutoCompoundPolicy
///
/// @notice Single-executor authorized policy that claims Morpho rewards from the Merkl distributor and optionally
///         swaps them to USDC and deposits into a Morpho vault — compounding the user's lending position.
///
/// @dev Properties:
///      - immutable Merkl distributor, MORPHO token, USDC token, and periphery addresses (set at deployment)
///      - pinned vault per config (single-vault v1)
///      - consent-gated: `convertAndReinvest` flag in config controls whether swapping is authorized
///      - executor-signed execution intents with nonce replay protection (inherited)
///      - recurring allowance bounds on compounded USDC (allowance window derived from policy validity window)
///      - post-execution MORPHO balance delta check prevents sweeping pre-existing MORPHO
///
///      The swap and deposit are handled by a stateless periphery contract (`AutoCompoundPeriphery`) because
///      the policy framework builds the full call plan before execution — the policy can't observe the swap
///      output to size the deposit dynamically. The periphery collapses swap + deposit into one call frame.
contract MorphoAutoCompoundPolicy is SingleExecutorAuthorizedPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Recurring deposit allowance parameters.
    ///
    /// @dev The allowance window bounds (start/end) are derived from the policy validity window
    ///      (`PolicyManager.policies(policy, policyId).validAfter/validUntil`).
    struct DepositLimitConfig {
        /// @dev Maximum USDC deposited per recurring period, in USDC smallest units.
        uint160 allowance;
        /// @dev Period length in seconds.
        uint40 period;
    }

    /// @notice Policy-specific config for auto-compounding Morpho rewards.
    struct AutoCompoundConfig {
        /// @dev Whether the user has authorized MORPHO → USDC conversion and vault deposit.
        ///      When false, the policy only claims rewards (no swap, no deposit).
        bool convertAndReinvest;
        /// @dev Morpho vault to deposit into (ignored when `convertAndReinvest` is false).
        address vault;
        /// @dev Uniswap V3 pool fee tier for MORPHO/USDC (ignored when `convertAndReinvest` is false).
        uint24 swapPoolFee;
        /// @dev Maximum acceptable slippage in basis points — reserved for future oracle-based validation
        ///      (ignored when `convertAndReinvest` is false).
        uint16 maxSlippageBps;
        /// @dev Recurring allowance on deposited USDC (ignored when `convertAndReinvest` is false).
        DepositLimitConfig depositLimit;
    }

    /// @notice Policy-specific execution payload.
    struct AutoCompoundActionData {
        /// @dev Cumulative claimable MORPHO amount for the Merkl proof.
        uint256 claimAmount;
        /// @dev Merkle proof from the Merkl API.
        bytes32[] claimProof;
        /// @dev Amount of MORPHO to swap (executor computes from cumulative - alreadyClaimed).
        ///      Must be zero when `convertAndReinvest` is false.
        uint256 swapAmountIn;
        /// @dev Minimum USDC to accept from the swap (sandwich protection).
        ///      Must be zero when `convertAndReinvest` is false.
        uint256 minAmountOut;
    }

    /// @notice Post-execution data passed from `_onSingleExecutorExecute` to `_onPostExecute`.
    struct PostExecData {
        /// @dev Account's MORPHO balance before the batch executed.
        uint256 morphoBalanceBefore;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Merkl rewards distributor contract.
    address public immutable MERKL_DISTRIBUTOR;

    /// @notice MORPHO token address.
    address public immutable MORPHO_TOKEN;

    /// @notice USDC token address.
    address public immutable USDC;

    /// @notice AutoCompoundPeriphery contract that handles the atomic swap + deposit.
    address public immutable PERIPHERY;

    /// @notice Recurring allowance state for USDC deposits.
    RecurringAllowance.State internal _depositLimitState;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when the Merkl distributor address has no deployed code.
    error MerklDistributorNotContract(address merklDistributor);

    /// @notice Thrown when the MORPHO token address has no deployed code.
    error MorphoTokenNotContract(address morphoToken);

    /// @notice Thrown when the USDC token address has no deployed code.
    error UsdcNotContract(address usdc);

    /// @notice Thrown when the periphery address has no deployed code.
    error PeripheryNotContract(address periphery);

    /// @notice Thrown when the vault address has no deployed code.
    error VaultNotContract(address vault);

    /// @notice Thrown when swap parameters are provided but `convertAndReinvest` is false.
    error SwapNotAuthorized();

    /// @notice Thrown when `swapAmountIn` is zero in compound mode.
    error ZeroSwapAmount();

    /// @notice Thrown when `maxSlippageBps` is out of valid range.
    error InvalidSlippageBps(uint16 maxSlippageBps);

    /// @notice Thrown when pre-existing MORPHO was consumed by the swap (balance delta check failed).
    ///
    /// @param morphoBefore Account's MORPHO balance before the batch.
    /// @param morphoAfter Account's MORPHO balance after the batch.
    error PreExistingMorphoConsumed(uint256 morphoBefore, uint256 morphoAfter);

    ////////////////////////////////////////////////////////////////
    ///                         Events                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted after a successful claim-only execution.
    ///
    /// @param policyId Policy identifier.
    /// @param account Account that claimed rewards.
    /// @param claimAmount Cumulative claim amount submitted to Merkl.
    event RewardsClaimed(bytes32 indexed policyId, address indexed account, uint256 claimAmount);

    /// @notice Emitted after a successful compound execution (claim + swap + deposit).
    ///
    /// @param policyId Policy identifier.
    /// @param account Account whose rewards were compounded.
    /// @param swapAmountIn MORPHO amount swapped.
    /// @param minAmountOut Minimum USDC accepted from the swap.
    event RewardsCompounded(
        bytes32 indexed policyId, address indexed account, uint256 swapAmountIn, uint256 minAmountOut
    );

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Deploys the policy with immutable protocol addresses.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` and `PAUSER_ROLE`.
    /// @param merklDistributor_ Merkl rewards distributor address.
    /// @param morphoToken_ MORPHO token address.
    /// @param usdc_ USDC token address.
    /// @param periphery_ AutoCompoundPeriphery contract address.
    constructor(
        address policyManager,
        address admin,
        address merklDistributor_,
        address morphoToken_,
        address usdc_,
        address periphery_
    ) SingleExecutorAuthorizedPolicy(policyManager, admin) {
        if (_isNotPersistentCode(merklDistributor_)) {
            revert MerklDistributorNotContract(merklDistributor_);
        }
        if (_isNotPersistentCode(morphoToken_)) revert MorphoTokenNotContract(morphoToken_);
        if (_isNotPersistentCode(usdc_)) revert UsdcNotContract(usdc_);
        if (_isNotPersistentCode(periphery_)) revert PeripheryNotContract(periphery_);

        MERKL_DISTRIBUTOR = merklDistributor_;
        MORPHO_TOKEN = morphoToken_;
        USDC = usdc_;
        PERIPHERY = periphery_;
    }

    ////////////////////////////////////////////////////////////////
    ///                 External View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Return recurring deposit limit usage for a policy instance.
    ///
    /// @dev Requires the config preimage so the contract can decode `depositLimit` without storing it.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param policyConfig Full config preimage bytes.
    ///
    /// @return lastUpdated Last stored period usage snapshot.
    /// @return current Current period usage computed from `depositLimit`.
    function getDepositLimitPeriodUsage(bytes32 policyId, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        _requireConfigHash(policyId, policyConfig);
        (, bytes memory policySpecificConfig) = _decodeSingleExecutorConfig(policyConfig);
        AutoCompoundConfig memory config = abi.decode(policySpecificConfig, (AutoCompoundConfig));

        lastUpdated = RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(
            _depositLimitState, policyId, _addTimeBoundsToDepositLimit(policyId, config.depositLimit)
        );
    }

    /// @notice Return the last stored recurring deposit usage for a policy instance.
    ///
    /// @param policyId Policy identifier for the binding.
    ///
    /// @return Last stored period usage snapshot.
    function getDepositLimitLastUpdated(bytes32 policyId)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc SingleExecutorAuthorizedPolicy
    ///
    /// @dev Validates config at install time. When `convertAndReinvest` is true, validates vault, pool fee,
    ///      slippage bounds, and deposit limit parameters.
    function _onSingleExecutorInstall(bytes32, address, SingleExecutorConfig memory, bytes memory policySpecificConfig)
        internal
        view
        override
    {
        AutoCompoundConfig memory config = abi.decode(policySpecificConfig, (AutoCompoundConfig));

        if (config.convertAndReinvest) {
            if (_isNotPersistentCode(config.vault)) revert VaultNotContract(config.vault);
            if (config.maxSlippageBps == 0 || config.maxSlippageBps >= 10_000) {
                revert InvalidSlippageBps(config.maxSlippageBps);
            }
            if (config.depositLimit.period == 0) revert RecurringAllowance.ZeroPeriod();
            if (config.depositLimit.allowance == 0) revert RecurringAllowance.ZeroAllowance();
        }
    }

    /// @inheritdoc SingleExecutorAuthorizedPolicy
    ///
    /// @dev Builds the claim-only or full compound call batch depending on `convertAndReinvest`.
    function _onSingleExecutorExecute(
        bytes32 policyId,
        address account,
        SingleExecutorConfig memory,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        AutoCompoundConfig memory config = abi.decode(policySpecificConfig, (AutoCompoundConfig));
        AutoCompoundActionData memory action = abi.decode(actionData, (AutoCompoundActionData));

        if (!config.convertAndReinvest) {
            return _buildClaimOnly(policyId, account, action);
        }

        return _buildCompound(policyId, account, config, action);
    }

    /// @dev In compound mode, verifies the MORPHO balance delta: the account should have at least as much
    ///      MORPHO after the batch as before, ensuring no pre-existing MORPHO was consumed by the swap.
    function _onPostExecute(bytes32, address account, bytes calldata postCallData) internal view override {
        // Claim-only mode passes empty postCallData — nothing to verify.
        if (postCallData.length == 0) return;

        PostExecData memory data = abi.decode(postCallData, (PostExecData));
        uint256 morphoAfter = IERC20(MORPHO_TOKEN).balanceOf(account);

        // The claim adds MORPHO, the swap removes it. In the happy path the net delta is roughly zero.
        // If the account's MORPHO balance decreased, pre-existing tokens were consumed.
        if (morphoAfter < data.morphoBalanceBefore) {
            revert PreExistingMorphoConsumed(data.morphoBalanceBefore, morphoAfter);
        }
    }

    ////////////////////////////////////////////////////////////////
    ///                   Private Functions                      ///
    ////////////////////////////////////////////////////////////////

    /// @dev Builds a claim-only call batch (single call to Merkl distributor).
    function _buildClaimOnly(bytes32 policyId, address account, AutoCompoundActionData memory action)
        private
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        // Reject swap parameters in claim-only mode.
        if (action.swapAmountIn > 0 || action.minAmountOut > 0) revert SwapNotAuthorized();

        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](1);
        calls[0] = _buildClaimCall(account, action);

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        // Empty postCallData signals claim-only mode to _onPostExecute.
        postCallData = "";

        emit RewardsClaimed(policyId, account, action.claimAmount);
    }

    /// @dev Builds a full compound call batch: claim → approve periphery → swapAndDeposit → zero-approve cleanup.
    function _buildCompound(
        bytes32 policyId,
        address account,
        AutoCompoundConfig memory config,
        AutoCompoundActionData memory action
    ) private returns (bytes memory accountCallData, bytes memory postCallData) {
        if (action.swapAmountIn == 0) revert ZeroSwapAmount();

        // Consume recurring allowance against minAmountOut (the guaranteed minimum USDC deposit).
        // The actual deposit may be slightly more if the swap gets a better price.
        RecurringAllowance.useLimit(
            _depositLimitState,
            policyId,
            _addTimeBoundsToDepositLimit(policyId, config.depositLimit),
            action.minAmountOut
        );

        // Snapshot MORPHO balance for the post-execution delta check.
        uint256 morphoBalanceBefore = IERC20(MORPHO_TOKEN).balanceOf(account);

        // Build 4-call batch: claim, approve periphery, swapAndDeposit, zero-approve cleanup.
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](4);

        // Call 1: Claim MORPHO from Merkl.
        calls[0] = _buildClaimCall(account, action);

        // Call 2: Approve MORPHO to periphery.
        calls[1] = CoinbaseSmartWallet.Call({
            target: MORPHO_TOKEN,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, PERIPHERY, action.swapAmountIn)
        });

        // Call 3: Periphery swaps MORPHO → USDC and deposits into vault.
        calls[2] = CoinbaseSmartWallet.Call({
            target: PERIPHERY,
            value: 0,
            data: abi.encodeWithSelector(
                AutoCompoundPeriphery.swapAndDeposit.selector,
                config.vault,
                action.swapAmountIn,
                action.minAmountOut,
                config.swapPoolFee,
                account
            )
        });

        // Call 4: Zero-approve cleanup (revoke any residual periphery approval).
        calls[3] = CoinbaseSmartWallet.Call({
            target: MORPHO_TOKEN, value: 0, data: abi.encodeWithSelector(IERC20.approve.selector, PERIPHERY, 0)
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = abi.encode(PostExecData({morphoBalanceBefore: morphoBalanceBefore}));

        emit RewardsCompounded(policyId, account, action.swapAmountIn, action.minAmountOut);
    }

    /// @dev Constructs the Merkl claim call for a single MORPHO token claim.
    function _buildClaimCall(address account, AutoCompoundActionData memory action)
        private
        view
        returns (CoinbaseSmartWallet.Call memory)
    {
        // Wrap single-element arrays for the Merkl distributor interface.
        address[] memory users = new address[](1);
        users[0] = account;

        address[] memory tokens = new address[](1);
        tokens[0] = MORPHO_TOKEN;

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = action.claimAmount;

        bytes32[][] memory proofs = new bytes32[][](1);
        proofs[0] = action.claimProof;

        return CoinbaseSmartWallet.Call({
            target: MERKL_DISTRIBUTOR,
            value: 0,
            data: abi.encodeWithSelector(IMerklDistributor.claim.selector, users, tokens, amounts, proofs)
        });
    }

    /// @dev Constructs a full `RecurringAllowance.Limit` by combining the caller-supplied `DepositLimitConfig`
    ///      with the policy's on-chain validity window from the PolicyManager.
    function _addTimeBoundsToDepositLimit(bytes32 policyId, DepositLimitConfig memory depositLimitConfig)
        internal
        view
        returns (RecurringAllowance.Limit memory)
    {
        (,,, uint40 validAfter, uint40 validUntil) = policyManager.policies(address(this), policyId);
        uint40 start = validAfter;
        uint40 end = validUntil == 0 ? type(uint40).max : validUntil;
        return RecurringAllowance.Limit({
            allowance: depositLimitConfig.allowance, period: depositLimitConfig.period, start: start, end: end
        });
    }

    /// @dev Returns the EIP-712 domain name and version used for executor signature verification.
    ///
    /// @return name    Domain name (`"Morpho Auto Compound Policy"`).
    /// @return version Domain version (`"1"`).
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Auto Compound Policy";
        version = "1";
    }
}
