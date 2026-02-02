// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {Policy} from "./Policy.sol";

/// @notice Template-method base for "Automated On-chain Actions" (AOA) policies.
/// @dev Enforces canonical ABI encoding shapes by owning the internal hook implementations:
///      - policyConfig = abi.encode(AOAConfig{account,executor}, bytes policySpecificConfig)
///      - policyData   = abi.encode(bytes actionData, bytes signature)
abstract contract AOAPolicy is Policy, AccessControl, Pausable, EIP712 {
    struct AOAConfig {
        address account;
        address executor;
    }

    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error InvalidAOAConfigAccount(address actual, address expected);
    error ZeroExecutor();
    error ZeroAdmin();
    error Unauthorized(address caller);
    error UninstallSignatureExpired(uint256 currentTimestamp, uint256 deadline);
    error CancelSignatureExpired(uint256 currentTimestamp, uint256 deadline);

    /// @dev Stored config hash per policy instance.
    mapping(bytes32 policyId => bytes32 configHash) internal _configHashByPolicyId;

    bytes32 public constant AOA_UNINSTALL_TYPEHASH =
        keccak256("AOAUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)");

    bytes32 public constant AOA_CANCEL_TYPEHASH =
        keccak256("AOACancel(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)");

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

    function _onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    )
        internal
        virtual
        override
    {
        // Account can always uninstall without providing config.
        if (caller == account) {
            _onAOAUninstall(policyId, account, caller);
            _deleteConfigHash(policyId);
            return;
        }

        // Non-account uninstallers must provide the installed config preimage.
        _requireConfigHash(policyId, policyConfig);
        (AOAConfig memory aoa,) = _decodeAOAConfig(account, policyConfig);

        // Optional auth:
        // - direct caller is executor, OR
        // - executor-signed uninstall intent (relayers allowed)
        if (caller != aoa.executor) {
            (bytes memory signature, uint256 deadline) = abi.decode(uninstallData, (bytes, uint256));
            if (deadline != 0 && block.timestamp > deadline) {
                revert UninstallSignatureExpired(block.timestamp, deadline);
            }
            bytes32 digest = _hashTypedData(
                keccak256(abi.encode(AOA_UNINSTALL_TYPEHASH, policyId, account, _configHashByPolicyId[policyId], deadline))
            );
            if (!_isValidExecutorSig(aoa.executor, digest, signature)) revert Unauthorized(caller);
        }

        _onAOAUninstall(policyId, account, aoa.executor);
        _deleteConfigHash(policyId);
    }

    function _onCancel(bytes32 policyId, address account, bytes calldata policyConfig, bytes calldata cancelData, address caller)
        internal
        override
    {
        // Account can always cancel.
        if (caller == account) return;

        // Non-account cancellers must be the configured executor (derivable from config) OR provide an executor signature.
        (AOAConfig memory aoa,) = _decodeAOAConfig(account, policyConfig);

        if (caller != aoa.executor) {
            (bytes memory signature, uint256 deadline) = abi.decode(cancelData, (bytes, uint256));
            if (deadline != 0 && block.timestamp > deadline) {
                revert CancelSignatureExpired(block.timestamp, deadline);
            }
            bytes32 digest = _hashTypedData(
                keccak256(abi.encode(AOA_CANCEL_TYPEHASH, policyId, account, keccak256(policyConfig), deadline))
            );
            if (!_isValidExecutorSig(aoa.executor, digest, signature)) revert Unauthorized(caller);
        }
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

