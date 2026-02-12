// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title uninstallTest
///
/// @notice Test contract for `PolicyManager.uninstall` (both policyId-mode and binding-mode).
contract uninstallTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts in policyId-mode when `policy` is zero or `policyId` is zero.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_policyIdMode_whenPolicyOrPolicyIdIsZero(address policy, bytes32 policyId) public {
        vm.skip(true);

        policy;
        policyId;
    }

    /// @notice Reverts in policyId-mode when the policyId is not installed.
    ///
    /// @dev Expects `PolicyManager.PolicyNotInstalled`.
    function test_reverts_policyIdMode_whenPolicyNotInstalled(bytes32 policyId) public {
        vm.skip(true);

        policyId;
    }

    /// @notice Reverts in binding-mode (pre-install) when `policyConfig` is empty.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_bindingMode_preInstall_whenPolicyConfigEmpty() public {
        vm.skip(true);
    }

    /// @notice Reverts in binding-mode (pre-install) when `policyConfig` hash does not match the binding commitment.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    function test_reverts_bindingMode_preInstall_whenPolicyConfigHashMismatch(bytes memory policyConfig) public {
        vm.skip(true);

        policyConfig;
    }

    /// @notice Reverts with `Unauthorized` when the policy uninstall hook reverts and caller is not the account.
    function test_reverts_whenPolicyHookReverts_andCallerNotAccount(address caller) public {
        vm.skip(true);

        caller;
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyUninstalled` when uninstalling an installed policy instance (policyId-mode).
    function test_emitsPolicyUninstalled_policyIdMode_installedLifecycle() public {
        vm.skip(true);
    }

    /// @notice Emits `PolicyUninstalled` when permanently disabling a pre-install policyId (binding-mode).
    function test_emitsPolicyUninstalled_bindingMode_preInstall() public {
        vm.skip(true);
    }

    /// @notice Uninstall is idempotent: uninstalling an already-uninstalled policyId is a no-op.
    function test_isIdempotent_whenAlreadyUninstalled_noHookNoEvent() public {
        vm.skip(true);
    }

    /// @notice Account can always uninstall an installed instance even if the policy hook reverts.
    function test_accountEscapeHatch_installedLifecycle_policyIdMode() public {
        vm.skip(true);
    }

    /// @notice In binding-mode installed lifecycle, uninstall uses the stored record account (not the payload binding account).
    function test_bindingMode_installedLifecycle_usesStoredRecordAccount() public {
        vm.skip(true);
    }
}

