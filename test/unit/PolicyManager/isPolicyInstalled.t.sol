// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyInstalledTest
///
/// @notice Test contract for `PolicyManager.isPolicyInstalled`.
contract isPolicyInstalledTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_returnsFalse_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns true after install (even if later uninstalled).
    function test_returnsTrue_afterInstall_evenIfLaterUninstalled() public {
        vm.skip(true);
    }
}

