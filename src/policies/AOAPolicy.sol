// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {Policy} from "./Policy.sol";

/// @notice Template-method base for "Automated On-chain Actions" (AOA) policies.
/// @dev Enforces canonical ABI encoding shapes by owning the internal hook implementations:
///      - policyConfig = abi.encode(AOAConfig{account,executor}, bytes policySpecificConfig)
///      - policyData   = abi.encode(bytes actionData, bytes signature)
abstract contract AOAPolicy is Policy, AccessControl, Pausable {
    struct AOAConfig {
        address account;
        address executor;
    }

    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error InvalidAOAConfigAccount(address actual, address expected);
    error ZeroExecutor();
    error ZeroAdmin();

    /// @dev Stored config hash per policy instance.
    mapping(bytes32 policyId => bytes32 configHash) internal _configHashByPolicyId;

    constructor(address policyManager, address admin) Policy(policyManager) {
        if (admin == address(0)) revert ZeroAdmin();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _storeConfigHash(bytes32 policyId, bytes calldata policyConfig) internal {
        _configHashByPolicyId[policyId] = keccak256(policyConfig);
    }

    function _deleteConfigHash(bytes32 policyId) internal {
        delete _configHashByPolicyId[policyId];
    }

    function _requireConfigHash(bytes32 policyId, bytes calldata policyConfig) internal view {
        bytes32 expected = _configHashByPolicyId[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);
    }

    function _decodeAOAConfig(address expectedAccount, bytes calldata policyConfig)
        internal
        pure
        returns (AOAConfig memory aoa, bytes memory policySpecificConfig)
    {
        (aoa, policySpecificConfig) = abi.decode(policyConfig, (AOAConfig, bytes));
        if (aoa.account != expectedAccount) revert InvalidAOAConfigAccount(aoa.account, expectedAccount);
        if (aoa.executor == address(0)) revert ZeroExecutor();
    }

    /// @dev Validate executor signature using the policy manager's validator (supports ERC-6492 side effects).
    function _isValidExecutorSig(address executor, bytes32 digest, bytes memory signature) internal returns (bool) {
        return POLICY_MANAGER.PUBLIC_ERC6492_VALIDATOR().isValidSignatureNowAllowSideEffects(executor, digest, signature);
    }

    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller) internal override {
        caller;
        _storeConfigHash(policyId, policyConfig);
        (AOAConfig memory aoa, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        _onAOAInstall(policyId, aoa, policySpecificConfig);
    }

    function _onUninstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        internal
        override
    {
        // Account can always uninstall without providing config.
        if (caller == account) {
            _onAOAUninstall(policyId, account, caller);
            _deleteConfigHash(policyId);
            return;
        }

        // Non-account uninstallers must provide the installed config preimage, and must be the configured executor.
        _requireConfigHash(policyId, policyConfig);
        (AOAConfig memory aoa,) = _decodeAOAConfig(account, policyConfig);
        if (caller != aoa.executor) revert InvalidSender(caller, aoa.executor);

        _onAOAUninstall(policyId, account, caller);
        _deleteConfigHash(policyId);
    }

    function _onCancel(bytes32, address account, bytes calldata policyConfig, address caller) internal pure override {
        // Account can always cancel.
        if (caller == account) return;

        // Non-account cancellers must be the configured executor (derivable from config).
        (AOAConfig memory aoa,) = _decodeAOAConfig(account, policyConfig);
        if (caller != aoa.executor) revert InvalidSender(caller, aoa.executor);
    }

    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal override whenNotPaused returns (bytes memory accountCallData, bytes memory postCallData) {
        _requireConfigHash(policyId, policyConfig);

        (AOAConfig memory aoa, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        (bytes memory actionData, bytes memory signature) = abi.decode(policyData, (bytes, bytes));

        return _onAOAExecute(policyId, aoa, policySpecificConfig, actionData, signature, caller);
    }

    function _onAOAInstall(bytes32 policyId, AOAConfig memory aoa, bytes memory policySpecificConfig) internal virtual {
        policyId;
        aoa;
        policySpecificConfig;
    }

    function _onAOAUninstall(bytes32 policyId, address account, address caller) internal virtual {
        policyId;
        account;
        caller;
    }

    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);
}

