// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../PolicyManager.sol";

/// @title Policy
///
/// @notice Base hook interface for policies managed by `PolicyManager`.
///
/// @dev Policies define authorization semantics and return an account call plan for execution. All external entrypoints
///      are callable only by the `PolicyManager`.
abstract contract Policy {
    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Native token sentinel used by this protocol (ERC-7528 convention).
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    /// @notice The `PolicyManager` instance authorized to call hooks.
    PolicyManager public immutable POLICY_MANAGER;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when a caller restriction is violated.
    ///
    /// @param sender Actual sender.
    /// @param expected Expected sender.
    error InvalidSender(address sender, address expected);

    ////////////////////////////////////////////////////////////////
    ///                        Modifiers                         ///
    ////////////////////////////////////////////////////////////////

    /// @notice Restricts execution to the configured `POLICY_MANAGER`.
    modifier onlyPolicyManager() {
        _requireSender(address(POLICY_MANAGER));
        _;
    }

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy and pins its manager.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call this policy's hooks.
    constructor(address policyManager) {
        POLICY_MANAGER = PolicyManager(policyManager);
    }

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy hook invoked during installation.
    ///
    /// @dev MUST revert if the policy refuses the installation.
    ///
    /// `policyId` is the EIP-712 struct hash of `binding` as computed by `PolicyManager`.
    /// `policyConfig` is the full config preimage bytes that match `binding.policyConfigHash`.
    ///
    /// @param policyId Deterministic policy identifier derived from the binding.
    /// @param account Account that installed the policy.
    /// @param policyConfig Full config preimage bytes.
    /// @param caller Effective caller forwarded by the manager (usually `msg.sender` of the manager call).
    function onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        external
        onlyPolicyManager
    {
        _onInstall(policyId, account, policyConfig, caller);
    }

    /// @notice Authorize the execution and build the account call and optional post-call (executed on the policy).
    ///
    /// @dev MUST revert on unauthorized execution.
    ///
    /// `caller` is the external caller of `PolicyManager.execute`.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account that authorized this policy instance.
    /// @param policyConfig Policy-defined config bytes (often the config preimage).
    /// @param policyData Policy-defined per-execution payload.
    /// @param caller External caller that invoked the manager.
    ///
    /// @return accountCallData ABI-encoded calldata to execute on the account (or empty for no-op).
    /// @return postCallData ABI-encoded calldata to execute on the policy after the account call (or empty for no-op).
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
    ///
    /// @dev Called by `PolicyManager.cancelPolicy` before installation. Policies can use this hook to authorize who is
    ///      allowed to cancel a pending installation intent (e.g., executor/guardian derived from `policyConfig`).
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account that would install the policy (from the binding).
    /// @param policyConfig Full config preimage bytes.
    /// @param cancelData Optional policy-defined authorization payload.
    /// @param caller External caller of the manager entrypoint.
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
    ///
    /// @dev Called by `PolicyManager` after the binding has been marked uninstalled.
    ///
    /// `policyConfig` MAY be empty. Policies can use it to re-hydrate authorization (e.g., dynamic executors)
    /// without requiring additional stored state.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param policyConfig Optional policy-defined config bytes (often the config preimage).
    /// @param uninstallData Optional policy-defined authorization payload.
    /// @param caller Effective caller forwarded by the manager.
    function onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    ) external onlyPolicyManager {
        _onUninstall(policyId, account, policyConfig, uninstallData, caller);
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @dev Policy-specific install hook. Revert to refuse installation.
    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller) internal virtual;

    /// @dev Policy-specific execute hook. Revert to refuse execution.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);

    /// @dev Policy-specific uninstall hook. Revert to refuse non-account uninstallation.
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

    ////////////////////////////////////////////////////////////////
    ///                 Internal View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @dev Requires `msg.sender` to equal `sender`.
    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }
}

