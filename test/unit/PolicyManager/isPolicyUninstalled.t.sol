// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyUninstalledTest
///
/// @notice Test contract for `PolicyManager.isPolicyUninstalled`.
contract isPolicyUninstalledTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns false when the policyId has never been uninstalled.
    function test_returnsFalse_whenNeverUninstalled() public {
        vm.skip(true);
    }

    /// @notice Returns true after uninstall.
    function test_returnsTrue_afterUninstall() public {
        vm.skip(true);
    }
}

