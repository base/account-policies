// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Policy} from "./Policy.sol";
import {SingleExecutorPolicy} from "./SingleExecutorPolicy.sol";

/// @title SingleExecutorAuthorizedPolicy
///
/// @notice Abstract base for single-executor policies that require an executor signature on every execution.
///
/// @dev Implements the template-method hooks from `SingleExecutorPolicy` for the "always-authorized" pattern:
///      - Install requires a non-zero executor address.
///      - Every execution must be signed by the configured executor.
///      - Uninstall by the account is free; uninstall by a relayer requires a signed uninstall intent.
///
///      Subclasses implement the `_onSingleExecutorExecute` hook to define policy-specific behavior.
abstract contract SingleExecutorAuthorizedPolicy is SingleExecutorPolicy {
    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy and grants the admin role.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` (controls pause/unpause).
    constructor(address policyManager, address admin) SingleExecutorPolicy(policyManager, admin) {}

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc Policy
    ///
    /// @dev Single-executor install hook: stores config hash, decodes `SingleExecutorConfig`, validates non-zero
    ///      executor, and calls `_onSingleExecutorInstall`.
    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig) internal override {
        _storeConfigHash(policyId, policyConfig);
        (SingleExecutorConfig memory singleExecutorConfig, bytes memory policySpecificConfig) =
            _decodeSingleExecutorConfig(policyConfig);
        if (singleExecutorConfig.executor == address(0)) revert ZeroExecutor();
        _onSingleExecutorInstall(policyId, account, singleExecutorConfig, policySpecificConfig);
    }

    /// @inheritdoc Policy
    ///
    /// @dev Single-executor uninstall hook: enforces executor authorization.
    ///      Account callers may uninstall freely; relayers must provide an executor-signed uninstall intent.
    function _onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    ) internal virtual override {
        // Account can always uninstall without providing config.
        if (caller == account) {
            _onSingleExecutorUninstall(policyId, account, caller);
            return;
        }

        bytes32 storedConfigHash = _configHashByPolicyId[policyId];
        // If the policyId was never installed, allow a pre-install uninstallation (permanent disable) authorized by
        // config.
        if (storedConfigHash == bytes32(0)) {
            (SingleExecutorConfig memory preinstallConfig,) = _decodeSingleExecutorConfig(policyConfig);

            // Executor authorization is always signature-based (relayers allowed).
            (bytes memory signature, uint256 deadline) = abi.decode(uninstallData, (bytes, uint256));
            if (deadline != 0 && block.timestamp > deadline) {
                revert SignatureExpired(block.timestamp, deadline);
            }

            bytes32 digest = _getUninstallDigest(policyId, account, keccak256(policyConfig), deadline);
            if (!_isValidExecutorSig(preinstallConfig.executor, digest, signature)) revert Unauthorized(caller);

            _onSingleExecutorUninstall(policyId, account, preinstallConfig.executor);
            return;
        }

        // Installed lifecycle: non-account uninstallers must provide the installed config preimage.
        _requireConfigHash(policyId, policyConfig);
        (SingleExecutorConfig memory singleExecutorConfig,) = _decodeSingleExecutorConfig(policyConfig);

        // Executor authorization is always signature-based (relayers allowed).
        (bytes memory signatureInstalled, uint256 deadlineInstalled) = abi.decode(uninstallData, (bytes, uint256));
        if (deadlineInstalled != 0 && block.timestamp > deadlineInstalled) {
            revert SignatureExpired(block.timestamp, deadlineInstalled);
        }
        bytes32 digestInstalled = _getUninstallDigest(policyId, account, storedConfigHash, deadlineInstalled);
        if (!_isValidExecutorSig(singleExecutorConfig.executor, digestInstalled, signatureInstalled)) {
            revert Unauthorized(caller);
        }

        _onSingleExecutorUninstall(policyId, account, singleExecutorConfig.executor);
    }

    /// @inheritdoc Policy
    ///
    /// @dev During replacement the account has already authorized the operation (via `replace()` or
    ///      `replaceWithSignature`), so executor authorization is redundant. Skip straight to cleanup.
    function _onUninstallForReplace(bytes32 policyId, address account, bytes calldata, bytes calldata, address, bytes32)
        internal
        virtual
        override
    {
        _onSingleExecutorUninstall(policyId, account, account);
    }

    /// @inheritdoc Policy
    ///
    /// @dev Single-executor execute hook: requires installed config, validates executor signature + nonce replay
    ///      protection for all executions, decodes canonical payload shapes, and delegates to
    ///      `_onSingleExecutorExecute`.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        if (executionData.length == 0) return (accountCallData, postCallData);
        _requireNotPaused();

        _requireConfigHash(policyId, policyConfig);

        (SingleExecutorConfig memory singleExecutorConfig, bytes memory policySpecificConfig) =
            _decodeSingleExecutorConfig(policyConfig);
        (SingleExecutorExecutionData memory singleExecutorExecutionData, bytes memory actionData) =
            abi.decode(executionData, (SingleExecutorExecutionData, bytes));

        _validateAndConsumeExecutionIntent(
            policyId, account, singleExecutorConfig.executor, singleExecutorExecutionData, actionData, caller
        );

        return _onSingleExecutorExecute(policyId, account, singleExecutorConfig, policySpecificConfig, actionData);
    }

    /// @notice Policy-specific install hook for single-executor authorized policies.
    ///
    /// @dev Override to initialize per-policy state.
    function _onSingleExecutorInstall(
        bytes32 policyId,
        address account,
        SingleExecutorConfig memory singleExecutorConfig,
        bytes memory policySpecificConfig
    ) internal virtual {
        policyId;
        account;
        singleExecutorConfig;
        policySpecificConfig;
    }

    /// @notice Policy-specific uninstall hook for single-executor authorized policies.
    ///
    /// @dev Override to clear per-policy state.
    function _onSingleExecutorUninstall(bytes32 policyId, address account, address caller) internal virtual {
        policyId;
        account;
        caller;
    }

    /// @notice Policy-specific execute hook for single-executor authorized policies.
    ///
    /// @dev Override to enforce execution authorization and build account/post-call calldata.
    function _onSingleExecutorExecute(
        bytes32 policyId,
        address account,
        SingleExecutorConfig memory singleExecutorConfig,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);
}
