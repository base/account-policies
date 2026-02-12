// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title policiesTest
///
/// @notice Test contract for `PolicyManager.policies` (auto-generated public mapping getter).
contract policiesTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns all-zero fields when the policyId has never been seen.
    function test_returnsZeros_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns stored binding fields after install.
    function test_returnsRecord_afterInstall() public {
        vm.skip(true);
    }

    /// @notice Returns `uninstalled = true` after uninstall.
    function test_returnsUninstalled_afterUninstall() public {
        vm.skip(true);
    }
}

