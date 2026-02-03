// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {IMorphoVault} from "../interfaces/morpho/IMorphoVault.sol";
import {AOAPolicy} from "./AOAPolicy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @notice Morpho vault deposit policy.
/// @dev Fixed vault, fixed receiver (the account), bounded amount.
contract MorphoLendPolicy is AOAPolicy {
    // Type declarations
    struct MorphoConfig {
        address vault;
        RecurringAllowance.Limit depositLimit;
    }

    struct LendData {
        uint256 assets; // The amount of assets to supply, in the loan token's smallest unit (i.e. ERC20 decimals)
        uint256 nonce; // Policy-defined execution nonce (used for replay protection and for signed execution intents).
    }

    // State variables
    bytes32 public constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash)");

    RecurringAllowance.State internal _depositLimitState;
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    // Errors
    error ZeroAmount();
    error ZeroVault();
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);
    error ZeroNonce();

    // Functions
    constructor(address policyManager, address admin) AOAPolicy(policyManager, admin) {}

    // External functions that are view
    /// @notice Return recurring deposit limit usage for a policy instance.
    /// @dev Requires the config preimage so the contract can decode `depositLimit` without storing it.
    function getDepositLimitPeriodUsage(bytes32 policyId, address account, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        _requireConfigHash(policyId, policyConfig);
        (AOAConfig memory aoa, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        aoa; // silence unused warning

        MorphoConfig memory cfg = abi.decode(policySpecificConfig, (MorphoConfig));
        cfg.depositLimit = _applyInstallWindowBoundsIfUnset(policyId, cfg.depositLimit);
        lastUpdated = RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(_depositLimitState, policyId, cfg.depositLimit);
    }

    /// @notice Return the last stored recurring deposit usage for a policy instance.
    function getDepositLimitLastUpdated(bytes32 policyId)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
    }

    // Internal functions
    function _onAOAInstall(bytes32, AOAConfig memory, bytes memory policySpecificConfig) internal override {
        MorphoConfig memory cfg = abi.decode(policySpecificConfig, (MorphoConfig));
        if (cfg.vault == address(0)) revert ZeroVault();
    }

    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        MorphoConfig memory cfg = abi.decode(policySpecificConfig, (MorphoConfig));
        if (cfg.vault == address(0)) revert ZeroVault();

        LendData memory ld = abi.decode(actionData, (LendData));
        if (ld.assets == 0) revert ZeroAmount();
        if (ld.nonce == 0) revert ZeroNonce();
        if (_usedNonces[policyId][ld.nonce]) revert ExecutionNonceAlreadyUsed(policyId, ld.nonce);

        bytes32 payloadHash = keccak256(actionData);
        bytes32 digest = _getExecutionDigest(policyId, aoa.account, _configHashByPolicyId[policyId], payloadHash);
        if (!_isValidExecutorSig(aoa.executor, digest, signature)) revert Unauthorized(caller);

        _usedNonces[policyId][ld.nonce] = true;

        RecurringAllowance.Limit memory depositLimit = _applyInstallWindowBoundsIfUnset(policyId, cfg.depositLimit);
        RecurringAllowance.useLimit(_depositLimitState, policyId, depositLimit, ld.assets);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildVaultDepositCall(cfg, aoa.account, ld.assets);

        // Build wallet call plan:
        // - approve
        // - protocol call
        if (approvalToken != address(0) && approvalSpender != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, ld.assets)
            });
            calls[1] = CoinbaseSmartWallet.Call({target: target, value: value, data: callData});
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        } else {
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, callData);
        }

        postCallData = "";
    }

    // Internal functions that are view
    function _getInstallWindowAsLimitBounds(bytes32 policyId) internal view returns (uint48 start, uint48 end) {
        (,,, uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.getPolicyRecord(address(this), policyId);
        start = uint48(validAfter);
        end = validUntil == 0 ? type(uint48).max : uint48(validUntil);
    }

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

    function _getExecutionDigest(bytes32 policyId, address account, bytes32 configHash, bytes32 policyDataHash)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedData(keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, account, configHash, policyDataHash)));
    }

    function _buildVaultDepositCall(MorphoConfig memory cfg, address receiver, uint256 assets)
        internal
        view
        returns (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender)
    {
        target = cfg.vault;
        value = 0;

        approvalToken = IMorphoVault(cfg.vault).asset();
        approvalSpender = cfg.vault;
        callData = abi.encodeWithSelector(IMorphoVault.deposit.selector, assets, receiver);
        return (target, value, callData, approvalToken, approvalSpender);
    }

    // Internal functions that are pure
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Lend Policy";
        version = "1";
    }
}

