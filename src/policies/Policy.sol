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
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Identifies whether a policy is being invoked as the old (uninstalled) or new (installed) side of a
    ///         replacement operation.
    ///
    /// @dev `PolicyManager.replace` and `PolicyManager.replaceWithSignature` will call `onReplace` on both the old and
    ///      new policies, passing the appropriate role value. Policies SHOULD prefer overriding the role-specific
    ///      `_onUninstallForReplace` / `_onInstallForReplace` hooks rather than branching on `role` themselves.
    enum ReplaceRole {
        OldPolicy,
        NewPolicy
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice The `PolicyManager` instance authorized to call hooks.
    PolicyManager public immutable POLICY_MANAGER;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when a caller restriction is violated.
    ///
    /// @param caller Actual caller.
    /// @param expected Expected sender.
    error InvalidCaller(address caller, address expected);

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
    /// `policyConfig` is the config bytes from the binding.
    ///
    /// @param policyId Deterministic policy identifier derived from the binding.
    /// @param account Account that installed the policy.
    /// @param policyConfig Full config preimage bytes.
    /// @param effectiveCaller Effective caller forwarded by the manager (usually `msg.sender` of the manager call).
    function onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address effectiveCaller)
        external
        onlyPolicyManager
    {
        _onInstall(policyId, account, policyConfig, effectiveCaller);
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
    /// @param executionData Policy-defined per-execution payload.
    /// @param caller External caller that invoked the manager.
    ///
    /// @return accountCallData ABI-encoded calldata to execute on the account (or empty for no-op).
    /// @return postCallData ABI-encoded calldata to execute on the policy after the account call (or empty for no-op).
    function onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) external onlyPolicyManager returns (bytes memory accountCallData, bytes memory postCallData) {
        return _onExecute(policyId, account, policyConfig, executionData, caller);
    }

    /// @notice Policy hook invoked during uninstallation.
    ///
    /// @dev Called by `PolicyManager` after the binding has been marked uninstalled.
    ///      MAY also be called to permanently disable a policyId before installation (pre-install uninstallation),
    ///      in which case `policyConfig` is expected to be the full config preimage bytes.
    ///
    /// `policyConfig` MAY be empty. Policies can use it to re-hydrate authorization (e.g., dynamic executors)
    /// without requiring additional stored state.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param policyConfig Optional policy-defined config bytes (often the config preimage).
    /// @param uninstallData Optional policy-defined authorization payload.
    /// @param effectiveCaller Effective caller forwarded by the manager.
    function onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address effectiveCaller
    ) external onlyPolicyManager {
        _onUninstall(policyId, account, policyConfig, uninstallData, effectiveCaller);
    }

    /// @notice Policy hook invoked during atomic replacement.
    ///
    /// @dev Called by `PolicyManager.replace` / `PolicyManager.replaceWithSignature` in lieu of separate `onUninstall`
    ///      + `onInstall`
    ///      calls so a policy can distinguish replacement from standalone lifecycle transitions.
    ///
    /// Default behavior:
    /// - `role == OldPolicy`: delegates to `_onUninstallForReplace(policyId, account, policyConfig, replaceData, otherPolicy, otherPolicyId, effectiveCaller)`
    /// - `role == NewPolicy`: delegates to `_onInstallForReplace(policyId, account, policyConfig, replaceData, otherPolicy, otherPolicyId, effectiveCaller)`
    ///
    /// @param policyId Policy identifier for this policy instance (old or new depending on `role`).
    /// @param account Account associated with the replacement.
    /// @param policyConfig Config bytes for this policy instance.
    /// @param replaceData Optional policy-defined replacement payload:
    /// - For `role == OldPolicy`, default implementation forwards this as `uninstallData`.
    /// - For `role == NewPolicy`, default implementation ignores it.
    /// @param otherPolicy The other policy contract involved in the replacement.
    /// @param otherPolicyId The other policyId involved in the replacement.
    /// @param role Whether this hook is being invoked for the old policy or the new policy.
    /// @param effectiveCaller Effective caller forwarded by the manager.
    function onReplace(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata replaceData,
        address otherPolicy,
        bytes32 otherPolicyId,
        ReplaceRole role,
        address effectiveCaller
    ) external onlyPolicyManager {
        if (role == ReplaceRole.OldPolicy) {
            _onUninstallForReplace(
                policyId, account, policyConfig, replaceData, otherPolicy, otherPolicyId, effectiveCaller
            );
            return;
        }

        _onInstallForReplace(policyId, account, policyConfig, replaceData, otherPolicy, otherPolicyId, effectiveCaller);
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
        bytes calldata executionData,
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

    /// @notice Policy-specific replacement uninstall hook.
    ///
    /// @dev Override to implement replacement-aware uninstallation logic.
    ///
    /// Default behavior: delegates to `_onUninstall(..., uninstallData=replaceData, caller=effectiveCaller)`.
    ///
    /// @param policyId Policy identifier for this (old) policy instance.
    /// @param account Account associated with the replacement.
    /// @param policyConfig Config bytes for this policy instance.
    /// @param replaceData Optional policy-defined replacement payload.
    /// @param otherPolicy The other policy contract involved in the replacement.
    /// @param otherPolicyId The other policyId involved in the replacement.
    /// @param effectiveCaller Effective caller forwarded by the manager.
    function _onUninstallForReplace(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata replaceData,
        address otherPolicy,
        bytes32 otherPolicyId,
        address effectiveCaller
    ) internal virtual {
        otherPolicy;
        otherPolicyId;
        _onUninstall(policyId, account, policyConfig, replaceData, effectiveCaller);
    }

    /// @notice Policy-specific replacement install hook.
    ///
    /// @dev Override to implement replacement-aware installation logic.
    ///
    /// Default behavior: delegates to `_onInstall(..., caller=effectiveCaller)`.
    ///
    /// @param policyId Policy identifier for this (new) policy instance.
    /// @param account Account associated with the replacement.
    /// @param policyConfig Config bytes for this policy instance.
    /// @param replaceData Optional policy-defined replacement payload.
    /// @param otherPolicy The other policy contract involved in the replacement.
    /// @param otherPolicyId The other policyId involved in the replacement.
    /// @param effectiveCaller Effective caller forwarded by the manager.
    function _onInstallForReplace(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata replaceData,
        address otherPolicy,
        bytes32 otherPolicyId,
        address effectiveCaller
    ) internal virtual {
        replaceData;
        otherPolicy;
        otherPolicyId;
        _onInstall(policyId, account, policyConfig, effectiveCaller);
    }

    ////////////////////////////////////////////////////////////////
    ///                 Internal View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @dev Requires `msg.sender` to equal `sender`.
    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidCaller(msg.sender, sender);
    }
}

