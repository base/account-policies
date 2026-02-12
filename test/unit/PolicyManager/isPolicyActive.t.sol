// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyActiveTest
///
/// @notice Test contract for `PolicyManager.isPolicyActive`.
contract isPolicyActiveTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_returnsFalse_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns true after install.
    function test_returnsTrue_afterInstall() public {
        vm.skip(true);
    }

    /// @notice Returns false after uninstall.
    function test_returnsFalse_afterUninstall() public {
        vm.skip(true);
    }
}

