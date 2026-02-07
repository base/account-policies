// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Id, Market, MarketParams, Position} from "../interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../interfaces/morpho/IMorphoBlue.sol";
import {IOracle} from "../interfaces/morpho/IOracle.sol";

import {AOAPolicy} from "./AOAPolicy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @title MorphoLoanProtectionPolicy
///
/// @notice AOA policy that supplies Morpho Blue collateral when an account's LTV crosses a trigger threshold.
///
/// @dev Hard-enforces:
///      - pinned Morpho Blue contract + pinned `marketId` (market params are looked up onchain and required to exist)
///      - executor-authorized execution intents (direct call or signed intent)
///      - trigger LTV threshold
///      - post-protection LTV bounds (min + max)
///      - recurring allowance budget (in collateral-token units)
///      - one active policy per (account, marketId)
contract MorphoLoanProtectionPolicy is AOAPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy-specific config for Morpho Blue liquidation protection.
    struct MorphoConfig {
        /// @dev Morpho Blue contract address.
        address morpho;
        /// @dev Morpho Blue market identifier.
        Id marketId;

        // LTV constraints in WAD (1e18 = 100%).
        /// @dev Position must be at or above this LTV (wad) to trigger protection.
        uint256 triggerLtv;
        /// @dev Projected post-top-up LTV (wad) must be at or above this minimum.
        uint256 minPostProtectionLtv;
        /// @dev Projected post-top-up LTV (wad) must be at or below this maximum.
        uint256 maxPostProtectionLtv;

        // Budget in collateral-token units (smallest unit).
        /// @dev Recurring top-up allowance bounds, denominated in collateral-token units.
        RecurringAllowance.Limit collateralLimit;
    }

    /// @notice Policy-specific execution payload for collateral top-ups.
    struct TopUpData {
        /// @dev Amount of collateral assets to supply (collateral token smallest units).
        uint256 topUpAssets;
        /// @dev Policy-defined execution nonce used for replay protection.
        uint256 nonce;
        /// @dev Optional signature expiry timestamp (seconds). Zero means “no expiry”.
        uint256 deadline;
        /// @dev Optional data forwarded to Morpho's callback.
        bytes callbackData;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice EIP-712 typehash for the inner top-up payload.
    ///
    /// @dev Inner signed struct: what the executor is authorizing for a specific execution.
    bytes32 public constant TOP_UP_DATA_TYPEHASH =
        keccak256("TopUpData(uint256 topUpAssets,uint256 nonce,uint256 deadline,bytes32 callbackDataHash)");

    /// @notice Tracks one active policy per (account, marketId).
    mapping(address account => mapping(bytes32 marketId => bytes32 policyId)) internal _activePolicyByMarket;

    /// @notice Stored market key per policy instance to support clean uninstallation.
    mapping(bytes32 policyId => bytes32 marketId) internal _marketIdByPolicyId;

    /// @notice Recurring allowance state (budget in collateral units).
    RecurringAllowance.State internal _collateralLimitState;

    /// @notice Replay protection for executor intents.
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when the Morpho market params for the pinned `marketId` are not found/initialized.
    error MarketNotFound(Id marketId);

    /// @notice Thrown when the Morpho Blue address is zero.
    error ZeroMorpho();

    /// @notice Thrown when the marketId is zero.
    error ZeroMarketId();

    /// @notice Thrown when attempting a zero-amount top-up.
    error ZeroAmount();

    /// @notice Thrown when the execution nonce is zero.
    error ZeroNonce();

    /// @notice Thrown when a nonce has already been used for this policyId.
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);

    /// @notice Thrown when the position is below the trigger LTV (i.e., is considered healthy).
    error HealthyPosition(uint256 currentLtv, uint256 triggerLtv);

    /// @notice Thrown when the projected post-top-up LTV remains above the maximum bound.
    error ProjectedLtvTooHigh(uint256 projectedLtv, uint256 maxPostLtv);

    /// @notice Thrown when the projected post-top-up LTV falls below the minimum bound (over-protection).
    error ProjectedLtvTooLow(uint256 projectedLtv, uint256 minPostLtv);

    /// @notice Thrown when the oracle price results in a zero collateral value.
    error ZeroCollateralValue();

    /// @notice Thrown when an account attempts to install multiple active policies for the same marketId.
    error PolicyAlreadyInstalledForMarket(address account, Id marketId);

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` (controls pause/unpause).
    constructor(address policyManager, address admin) AOAPolicy(policyManager, admin) {}

    ////////////////////////////////////////////////////////////////
    ///                 External View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Return recurring collateral limit usage for a policy instance.
    ///
    /// @dev Requires the config preimage so the contract can decode `collateralLimit` without storing it.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param policyConfig Full config preimage bytes.
    ///
    /// @return lastUpdated Last stored period usage snapshot.
    /// @return current Current period usage computed from `collateralLimit`.
    function getCollateralLimitPeriodUsage(bytes32 policyId, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        _requireConfigHash(policyId, policyConfig);
        address account = POLICY_MANAGER.getAccountForPolicy(address(this), policyId);
        (AOAConfig memory aoa, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        aoa; // silence unused warning

        MorphoConfig memory config = abi.decode(policySpecificConfig, (MorphoConfig));
        config.collateralLimit = _applyInstallWindowBoundsIfUnset(policyId, config.collateralLimit);
        lastUpdated = RecurringAllowance.getLastUpdated(_collateralLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(_collateralLimitState, policyId, config.collateralLimit);
    }

    /// @notice Return the last stored recurring collateral usage for a policy instance.
    ///
    /// @param policyId Policy identifier for the binding.
    ///
    /// @return Last stored period usage snapshot.
    function getCollateralLimitLastUpdated(bytes32 policyId)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return RecurringAllowance.getLastUpdated(_collateralLimitState, policyId);
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Validates config, enforces one-policy-per-market, and stores market linkage for uninstall.
    function _onAOAInstall(bytes32 policyId, AOAConfig memory aoa, bytes memory policySpecificConfig)
        internal
        override
    {
        MorphoConfig memory config = abi.decode(policySpecificConfig, (MorphoConfig));
        if (config.morpho == address(0)) revert ZeroMorpho();
        if (Id.unwrap(config.marketId) == bytes32(0)) revert ZeroMarketId();

        // Ensure the pinned market exists on this Morpho instance.
        _requireMarketParams(config.morpho, config.marketId);

        // Ensure only one active policy per (account, market).
        bytes32 marketKey = Id.unwrap(config.marketId);
        if (_activePolicyByMarket[aoa.account][marketKey] != bytes32(0)) {
            revert PolicyAlreadyInstalledForMarket(aoa.account, config.marketId);
        }
        _activePolicyByMarket[aoa.account][marketKey] = policyId;
        _marketIdByPolicyId[policyId] = marketKey;
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Clears per-install state for a policy instance.
    function _onAOAUninstall(bytes32 policyId, address account, address) internal override {
        _clearInstallState(policyId, account);
    }

    /// @dev Clears per-install state mappings if still pointing at this policyId.
    function _clearInstallState(bytes32 policyId, address account) internal {
        bytes32 marketKey = _marketIdByPolicyId[policyId];
        if (marketKey != bytes32(0) && _activePolicyByMarket[account][marketKey] == policyId) {
            delete _activePolicyByMarket[account][marketKey];
        }
        delete _marketIdByPolicyId[policyId];
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Executes a collateral top-up, enforcing executor authorization, nonce replay protection, LTV bounds, and
    ///      recurring allowance bounds.
    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        MorphoConfig memory config = abi.decode(policySpecificConfig, (MorphoConfig));
        MarketParams memory marketParams = _requireMarketParams(config.morpho, config.marketId);
        TopUpData memory topUpData = abi.decode(actionData, (TopUpData));

        bytes32 expectedConfigHash = _configHashByPolicyId[policyId];
        _validatePolicyData(policyId, aoa.account, expectedConfigHash, aoa.executor, topUpData, signature, caller);
        _enforceLtvBounds(config, marketParams, aoa.account, topUpData.topUpAssets);

        // Enforce recurring budget in collateral-token units.
        RecurringAllowance.Limit memory collateralLimit =
            _applyInstallWindowBoundsIfUnset(policyId, config.collateralLimit);
        RecurringAllowance.useLimit(_collateralLimitState, policyId, collateralLimit, topUpData.topUpAssets);

        // Build wallet call plan:
        // - approve(collateralToken, morpho, amount)
        // - morpho.supplyCollateral(marketParams, amount, account, callbackData)
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0] = CoinbaseSmartWallet.Call({
            target: marketParams.collateralToken,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, config.morpho, topUpData.topUpAssets)
        });
        calls[1] = CoinbaseSmartWallet.Call({
            target: config.morpho,
            value: 0,
            data: abi.encodeWithSelector(
                IMorphoBlue.supplyCollateral.selector,
                marketParams,
                topUpData.topUpAssets,
                aoa.account,
                topUpData.callbackData
            )
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = "";
    }

    /// @dev Validates and consumes an executor-signed execution intent (deadline + nonce replay protection).
    function _validatePolicyData(
        bytes32 policyId,
        address account,
        bytes32 expectedConfigHash,
        address executor,
        TopUpData memory topUpData,
        bytes memory signature,
        address caller
    ) internal {
        if (topUpData.topUpAssets == 0) revert ZeroAmount();
        if (topUpData.nonce == 0) revert ZeroNonce();
        if (topUpData.deadline != 0 && block.timestamp > topUpData.deadline) {
            revert SignatureExpired(block.timestamp, topUpData.deadline);
        }
        if (_usedNonces[policyId][topUpData.nonce]) revert ExecutionNonceAlreadyUsed(policyId, topUpData.nonce);

        bytes32 callbackHash = keccak256(topUpData.callbackData);
        bytes32 topUpDataHash = keccak256(
            abi.encode(TOP_UP_DATA_TYPEHASH, topUpData.topUpAssets, topUpData.nonce, topUpData.deadline, callbackHash)
        );

        bytes32 digest = _getExecutionDigest(policyId, account, expectedConfigHash, topUpDataHash);
        bool ok = _isValidExecutorSig(executor, digest, signature);
        if (!ok) revert Unauthorized(caller);

        _usedNonces[policyId][topUpData.nonce] = true;
    }

    /// @dev Enforces trigger and post-top-up LTV bounds using current position, market totals, and oracle price.
    function _enforceLtvBounds(
        MorphoConfig memory config,
        MarketParams memory marketParams,
        address account,
        uint256 topUpAssets
    ) internal view {
        (uint256 currentLtv, uint256 projectedLtv) = _computeLtvPair(config, marketParams, account, topUpAssets);
        if (currentLtv < config.triggerLtv) revert HealthyPosition(currentLtv, config.triggerLtv);
        if (projectedLtv > config.maxPostProtectionLtv) {
            revert ProjectedLtvTooHigh(projectedLtv, config.maxPostProtectionLtv);
        }
        if (projectedLtv < config.minPostProtectionLtv) {
            revert ProjectedLtvTooLow(projectedLtv, config.minPostProtectionLtv);
        }
    }

    ////////////////////////////////////////////////////////////////
    ///                 Internal Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Looks up market params from `marketId` and reverts if the market is not initialized.
    ///
    /// @param morphoAddress Morpho Blue contract address.
    /// @param marketId Market identifier.
    ///
    /// @return marketParams Market parameters for the given marketId.
    function _requireMarketParams(address morphoAddress, Id marketId)
        internal
        view
        returns (MarketParams memory marketParams)
    {
        marketParams = IMorphoBlue(morphoAddress).idToMarketParams(marketId);
        // Treat zeroed params as "market does not exist / not initialized on this Morpho instance".
        if (
            marketParams.loanToken == address(0) || marketParams.collateralToken == address(0)
                || marketParams.oracle == address(0) || marketParams.irm == address(0) || marketParams.lltv == 0
        ) revert MarketNotFound(marketId);
    }

    /// @dev Returns the policy's install window encoded as allowance bounds.
    function _getInstallWindowAsLimitBounds(bytes32 policyId) internal view returns (uint48 start, uint48 end) {
        (,,, uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.getPolicyRecord(address(this), policyId);
        start = uint48(validAfter);
        end = validUntil == 0 ? type(uint48).max : uint48(validUntil);
    }

    /// @dev Applies install window bounds if the config uses the (start=0,end=0) sentinel.
    function _applyInstallWindowBoundsIfUnset(bytes32 policyId, RecurringAllowance.Limit memory limit)
        internal
        view
        returns (RecurringAllowance.Limit memory)
    {
        // Sentinel: if config leaves both timestamps zero, bind allowance to the policy install window.
        if (limit.start == 0 && limit.end == 0) {
            (limit.start, limit.end) = _getInstallWindowAsLimitBounds(policyId);
        }
        return limit;
    }

    /// @dev Computes the current LTV and projected post-top-up LTV (wad) for the pinned market and account position.
    function _computeLtvPair(
        MorphoConfig memory config,
        MarketParams memory marketParams,
        address account,
        uint256 topUpAssets
    ) internal view returns (uint256 currentLtvWad, uint256 projectedLtvWad) {
        IMorphoBlue morphoBlue = IMorphoBlue(config.morpho);
        Position memory position = morphoBlue.position(config.marketId, account);
        Market memory market = morphoBlue.market(config.marketId);

        uint256 collateralBefore = uint256(position.collateral);
        uint256 collateralAfter = collateralBefore + topUpAssets;

        // Debt assets derived from borrow shares and market totals.
        uint256 debtAssets;
        uint256 totalBorrowShares = uint256(market.totalBorrowShares);
        if (totalBorrowShares == 0) {
            debtAssets = 0;
        } else {
            debtAssets =
                Math.mulDiv(uint256(position.borrowShares), uint256(market.totalBorrowAssets), totalBorrowShares);
        }

        uint256 price = IOracle(marketParams.oracle).price(); // 1e36 scaled

        uint256 collateralValueBefore = Math.mulDiv(collateralBefore, price, 1e36);
        uint256 collateralValueAfter = Math.mulDiv(collateralAfter, price, 1e36);
        if (collateralValueBefore == 0 || collateralValueAfter == 0) revert ZeroCollateralValue();

        currentLtvWad = Math.mulDiv(debtAssets, 1e18, collateralValueBefore);
        projectedLtvWad = Math.mulDiv(debtAssets, 1e18, collateralValueAfter);
    }

    /// @dev EIP-712 domain metadata.
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Loan Protection Policy";
        version = "1";
    }
}

