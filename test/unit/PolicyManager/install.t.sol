// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title installTest
///
/// @notice Test contract for `PolicyManager.install`.
contract installTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller is not `binding.account`.
    ///
    /// @dev Expects `PolicyManager.InvalidSender`.
    function test_reverts_whenCallerNotAccount(address caller) public {
        vm.skip(true);

        caller;
    }

    /// @notice Reverts when the policyId has been uninstalled (prevents future installs).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenPolicyIsDisabled() public {
        vm.skip(true);
    }

    /// @notice Reverts when `policyConfig` hash does not match `binding.policyConfigHash`.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    function test_reverts_whenPolicyConfigHashMismatch(bytes memory policyConfig) public {
        vm.skip(true);

        policyConfig;
    }

    /// @notice Reverts when current timestamp is before `binding.validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    function test_reverts_whenBeforeValidAfter(uint40 validAfter) public {
        vm.skip(true);

        validAfter;
    }

    /// @notice Reverts when current timestamp is at/after `binding.validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    function test_reverts_whenAfterValidUntil(uint40 validUntil) public {
        vm.skip(true);

        validUntil;
    }

    /// @notice Bubbles a revert when the policy's `onInstall` hook reverts.
    ///
    /// @dev Expects the policy-defined revert to bubble from `Policy(policy).onInstall(...)`.
    function test_reverts_whenPolicyOnInstallReverts() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyInstalled` on first install.
    function test_emitsPolicyInstalled() public {
        vm.skip(true);
    }

    /// @notice Installs a policy instance and writes a lifecycle record.
    ///
    /// @dev Verifies that `policies(policy, policyId)` reflects binding fields.
    function test_installs_andStoresRecord() public {
        vm.skip(true);
    }

    /// @notice Calls the policy hook with the account as effective caller.
    ///
    /// @dev Verifies `policy.onInstall(..., effectiveCaller)` receives `binding.account` as `effectiveCaller`.
    function test_callsOnInstall_withAccountAsCaller() public {
        vm.skip(true);
    }

    /// @notice Allows installing multiple otherwise identical bindings via distinct salts.
    ///
    /// @dev Same (account, policy, configHash) but different salts => different policyIds => both installable.
    function test_allowsMultipleInstalls_withDifferentSalts(uint256 saltA, uint256 saltB) public {
        vm.skip(true);

        saltA;
        saltB;
    }

    /// @notice Stores `validAfter`/`validUntil` from the binding into the policy record.
    function test_storesValidityWindow_fieldsInRecord(uint40 validAfter, uint40 validUntil) public {
        vm.skip(true);

        validAfter;
        validUntil;
    }

    // =============================================================
    // Edge cases
    // =============================================================

    /// @notice Installing an already-installed policyId is a no-op (idempotent).
    ///
    /// @dev Second install returns the same policyId and does not call hooks or emit `PolicyInstalled`.
    function test_isIdempotent_noHookNoEventOnSecondInstall() public {
        vm.skip(true);
    }

    /// @notice Reinstalling a previously uninstalled policyId remains blocked.
    ///
    /// @dev After uninstallation, any future install attempt for that policyId must revert `PolicyIsDisabled`.
    function test_reinstall_afterUninstall_stillBlocked() public {
        vm.skip(true);
    }

    /// @notice Empty `policyConfig` is allowed when the binding commits to its hash.
    function test_allowsEmptyPolicyConfig_whenHashMatches() public {
        vm.skip(true);
    }

    /// @notice Behavior when `binding.policy` is the zero address.
    ///
    /// @dev Decide whether this should revert (preferred) or succeed as a no-op policy.
    function test_whenPolicyIsZeroAddress_behavior() public {
        vm.skip(true);
    }
}

