// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {IMorphoVault} from "../interfaces/morpho/IMorphoVault.sol";
import {AOAPolicy} from "./AOAPolicy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @title MorphoLendPolicy
///
/// @notice AOA policy that deposits assets into a fixed Morpho vault on behalf of an account.
///
/// @dev Properties:
///      - fixed vault (pinned in config)
///      - fixed receiver (the account)
///      - executor-signed execution intents
///      - recurring allowance bounds on deposited assets
contract MorphoLendPolicy is AOAPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy-specific config for lending into a pinned Morpho vault.
    struct LendPolicyConfig {
        /// @dev Morpho vault to deposit into.
        address vault;
        /// @dev Recurring deposit allowance bounds.
        RecurringAllowance.Limit depositLimit;
    }

    /// @notice Policy-specific execution payload for deposits.
    struct LendData {
        /// @dev Amount of assets to deposit, in the vault asset token's smallest unit (ERC20 decimals).
        uint256 depositAssets;
        /// @dev Policy-defined execution nonce used for replay protection (and signed intents).
        uint256 nonce;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Recurring allowance state for deposits.
    RecurringAllowance.State internal _depositLimitState;

    /// @notice Tracks used nonces per policyId to prevent replay of signed executions.
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to deposit zero assets.
    error ZeroAmount();

    /// @notice Thrown when the vault address is zero.
    error ZeroVault();

    /// @notice Thrown when the execution nonce has already been used for this policyId.
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);

    /// @notice Thrown when the execution nonce is zero.
    error ZeroNonce();

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

    /// @notice Return recurring deposit limit usage for a policy instance.
    ///
    /// @dev Requires the config preimage so the contract can decode `depositLimit` without storing it.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param policyConfig Full config preimage bytes.
    ///
    /// @return lastUpdated Last stored period usage snapshot.
    /// @return current Current period usage computed from `depositLimit`.
    function getDepositLimitPeriodUsage(bytes32 policyId, address account, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        _requireConfigHash(policyId, policyConfig);
        (, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);

        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        lendPolicyConfig.depositLimit = _applyValidityWindowBoundsIfUnset(policyId, lendPolicyConfig.depositLimit);
        lastUpdated = RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(_depositLimitState, policyId, lendPolicyConfig.depositLimit);
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

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Validates Morpho vault config at install time.
    function _onAOAInstall(bytes32, AOAConfig memory, bytes memory policySpecificConfig) internal override {
        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        if (lendPolicyConfig.vault == address(0)) revert ZeroVault();
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Executes a Morpho vault deposit, enforcing executor authorization, nonce replay protection, and
    ///      recurring allowance bounds.
    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoaConfig,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        if (lendPolicyConfig.vault == address(0)) revert ZeroVault();

        LendData memory lendData = abi.decode(actionData, (LendData));
        if (lendData.depositAssets == 0) revert ZeroAmount();
        if (lendData.nonce == 0) revert ZeroNonce();
        if (_usedNonces[policyId][lendData.nonce]) revert ExecutionNonceAlreadyUsed(policyId, lendData.nonce);

        bytes32 payloadHash = keccak256(actionData);
        bytes32 digest = _getExecutionDigest(policyId, aoaConfig.account, payloadHash);
        if (!_isValidExecutorSig(aoaConfig.executor, digest, signature)) revert Unauthorized(caller);

        _usedNonces[policyId][lendData.nonce] = true;

        RecurringAllowance.Limit memory depositLimit =
            _applyValidityWindowBoundsIfUnset(policyId, lendPolicyConfig.depositLimit);
        RecurringAllowance.useLimit(_depositLimitState, policyId, depositLimit, lendData.depositAssets);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildVaultDepositCall(lendPolicyConfig, aoaConfig.account, lendData.depositAssets);

        // Build wallet call plan:
        // - approve
        // - protocol call
        if (approvalToken != address(0) && approvalSpender != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, lendData.depositAssets)
            });
            calls[1] = CoinbaseSmartWallet.Call({target: target, value: value, data: callData});
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        } else {
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, callData);
        }

        postCallData = "";
    }

    ////////////////////////////////////////////////////////////////
    ///                 Internal Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @dev Returns the policy's validity window encoded as allowance bounds.
    function _getValidityWindowAsLimitBounds(bytes32 policyId) internal view returns (uint48 start, uint48 end) {
        (,,, uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.getPolicyRecord(address(this), policyId);
        start = uint48(validAfter);
        end = validUntil == 0 ? type(uint48).max : uint48(validUntil);
    }

    /// @dev Applies validity window bounds if the config uses the (start=0,end=0) sentinel.
    function _applyValidityWindowBoundsIfUnset(bytes32 policyId, RecurringAllowance.Limit memory limit)
        internal
        view
        returns (RecurringAllowance.Limit memory)
    {
        // Sentinel: if config leaves both timestamps zero, bind allowance to the policy validity window.
        if (limit.start == 0 && limit.end == 0) {
            (limit.start, limit.end) = _getValidityWindowAsLimitBounds(policyId);
        }
        return limit;
    }

    /// @dev Builds the underlying vault deposit call and approval requirements.
    function _buildVaultDepositCall(LendPolicyConfig memory lendPolicyConfig, address receiver, uint256 depositAssets)
        internal
        view
        returns (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender)
    {
        target = lendPolicyConfig.vault;
        value = 0;

        approvalToken = IMorphoVault(lendPolicyConfig.vault).asset();
        approvalSpender = lendPolicyConfig.vault;
        callData = abi.encodeWithSelector(IMorphoVault.deposit.selector, depositAssets, receiver);
        return (target, value, callData, approvalToken, approvalSpender);
    }

    /// @dev EIP-712 domain metadata.
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Lend Policy";
        version = "1";
    }
}

