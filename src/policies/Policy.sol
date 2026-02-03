// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../PolicyManager.sol";

/// @notice A policy defines authorization semantics and returns a wallet call plan.
abstract contract Policy {
    // State variables
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    PolicyManager public immutable POLICY_MANAGER;

    // Errors
    error InvalidSender(address sender, address expected);

    // Modifiers
    modifier onlyPolicyManager() {
        _requireSender(address(POLICY_MANAGER));
        _;
    }

    // Functions
    constructor(address policyManager) {
        POLICY_MANAGER = PolicyManager(policyManager);
    }

    /// @notice Policy hook invoked during installation.
    /// @dev MUST revert if the policy refuses the installation.
    ///
    /// `policyId` is the EIP-712 struct hash of `binding` as computed by `PolicyManager`.
    /// `policyConfig` is the full config preimage bytes that match `binding.policyConfigHash`.
    function onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        external
        onlyPolicyManager
    {
        _onInstall(policyId, account, policyConfig, caller);
    }

    /// @notice Authorize the execution and build the account call and optional post-call (executed on the policy).
    /// @dev MUST revert on unauthorized execution.
    ///
    /// `caller` is the external caller of `PolicyManager.execute`.
    function onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) external onlyPolicyManager returns (bytes memory accountCallData, bytes memory postCallData) {
        return _onExecute(policyId, account, policyConfig, policyData, caller);
    }

    /// @notice Policy hook invoked during pre-install cancellation.
    /// @dev Called by `PolicyManager.cancelPolicy` before installation. Policies can use this hook to authorize who is
    ///      allowed to cancel a pending installation intent (e.g., executor/guardian derived from `policyConfig`).
    function onCancel(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata cancelData,
        address caller
    ) external onlyPolicyManager {
        _onCancel(policyId, account, policyConfig, cancelData, caller);
    }

    /// @notice Policy hook invoked during uninstallation.
    /// @dev Called by `PolicyManager` after the binding has been marked uninstalled.
    ///
    /// `policyConfig` MAY be empty. Policies can use it to re-hydrate authorization (e.g., dynamic executors)
    /// without requiring additional stored state.
    function onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    ) external onlyPolicyManager {
        _onUninstall(policyId, account, policyConfig, uninstallData, caller);
    }

    // Internal functions
    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller) internal virtual;

    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);

    function _onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    ) internal virtual;

    /// @dev Default: only the account can cancel. Policies can override to allow other roles.
    function _onCancel(bytes32, address account, bytes calldata, bytes calldata, address caller) internal virtual {
        if (caller != account) revert InvalidSender(caller, account);
    }

    // Internal functions that are view
    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }
}

