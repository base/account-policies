// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";

/// @title gettersTest
///
/// @notice Test contract for `PolicyManager` view/pure getters and read helpers.
contract gettersTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // policies(policy, policyId)
    // =============================================================

    /// @notice Returns all-zero fields when the policyId has never been seen.
    function test_policies_returnsZeros_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns stored binding fields after install.
    function test_policies_returnsRecord_afterInstall() public {
        vm.skip(true);
    }

    /// @notice Returns `uninstalled = true` after uninstall.
    function test_policies_returnsUninstalled_afterUninstall() public {
        vm.skip(true);
    }

    // =============================================================
    // getAccountsForPolicies
    // =============================================================

    /// @notice Returns an array of the same length as `policyIds`.
    function test_getAccountsForPolicies_returnsSameLength(uint256 len) public {
        vm.skip(true);

        len;
    }

    /// @notice Returns zero address for policyIds that have never been installed.
    function test_getAccountsForPolicies_returnsZeroForUnknownPolicyIds(bytes32 policyId) public {
        vm.skip(true);

        policyId;
    }

    /// @notice Returns the stored account for installed policyIds.
    function test_getAccountsForPolicies_returnsAccountForInstalledPolicyIds() public {
        vm.skip(true);
    }

    // =============================================================
    // getPolicyRecords
    // =============================================================

    /// @notice Returns arrays with the same length as `policyIds`.
    function test_getPolicyRecords_returnsSameLength(uint256 len) public {
        vm.skip(true);

        len;
    }

    /// @notice Returns default (zero) record fields for unknown policyIds.
    function test_getPolicyRecords_returnsZerosForUnknownPolicyIds(bytes32 policyId) public {
        vm.skip(true);

        policyId;
    }

    /// @notice Returns stored record fields for installed policyIds.
    function test_getPolicyRecords_returnsRecordForInstalledPolicyIds() public {
        vm.skip(true);
    }

    /// @notice Returns `uninstalled = true` for uninstalled policyIds.
    function test_getPolicyRecords_returnsUninstalledForUninstalledPolicyIds() public {
        vm.skip(true);
    }

    // =============================================================
    // getPolicyId
    // =============================================================

    /// @notice Produces the same policyId for the same binding inputs.
    function test_getPolicyId_isDeterministic() public {
        vm.skip(true);
    }

    /// @notice Changing `salt` changes the policyId.
    function test_getPolicyId_changesWithSalt(uint256 saltA, uint256 saltB) public {
        vm.skip(true);

        saltA;
        saltB;
    }

    /// @notice Changing `policyConfigHash` changes the policyId.
    function test_getPolicyId_changesWithPolicyConfigHash(bytes32 policyConfigHashA, bytes32 policyConfigHashB) public {
        vm.skip(true);

        policyConfigHashA;
        policyConfigHashB;
    }

    /// @notice Changing the validity window changes the policyId.
    function test_getPolicyId_changesWithValidityWindow(uint40 validAfter, uint40 validUntil) public {
        vm.skip(true);

        validAfter;
        validUntil;
    }

    /// @notice Matches the `POLICY_BINDING_TYPEHASH` field order (regression test against accidental reorder).
    function test_getPolicyId_matchesTypehashFieldOrder() public {
        vm.skip(true);
    }

    // =============================================================
    // isPolicyInstalled / isPolicyUninstalled / isPolicyActive / isPolicyActiveNow
    // =============================================================

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyInstalled_returnsFalse_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns true after install (even if later uninstalled).
    function test_isPolicyInstalled_returnsTrue_afterInstall_evenIfLaterUninstalled() public {
        vm.skip(true);
    }

    /// @notice Returns false when the policyId has never been uninstalled.
    function test_isPolicyUninstalled_returnsFalse_whenNeverUninstalled() public {
        vm.skip(true);
    }

    /// @notice Returns true after uninstall.
    function test_isPolicyUninstalled_returnsTrue_afterUninstall() public {
        vm.skip(true);
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyActive_returnsFalse_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns true after install.
    function test_isPolicyActive_returnsTrue_afterInstall() public {
        vm.skip(true);
    }

    /// @notice Returns false after uninstall.
    function test_isPolicyActive_returnsFalse_afterUninstall() public {
        vm.skip(true);
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_isPolicyActiveNow_returnsFalse_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns false when the policy is uninstalled.
    function test_isPolicyActiveNow_returnsFalse_whenUninstalled() public {
        vm.skip(true);
    }

    /// @notice Returns false when current timestamp is before `validAfter`.
    function test_isPolicyActiveNow_returnsFalse_whenBeforeValidAfter(uint40 validAfter) public {
        vm.skip(true);

        validAfter;
    }

    /// @notice Returns false when current timestamp is at/after `validUntil`.
    function test_isPolicyActiveNow_returnsFalse_whenAfterValidUntil(uint40 validUntil) public {
        vm.skip(true);

        validUntil;
    }

    /// @notice Returns true when installed, not uninstalled, and within the validity window.
    function test_isPolicyActiveNow_returnsTrue_whenWithinValidityWindow() public {
        vm.skip(true);
    }
}

