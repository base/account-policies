// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyActiveNowTest
///
/// @notice Test contract for `PolicyManager.isPolicyActiveNow`.
contract isPolicyActiveNowTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns false when the policyId has never been installed.
    function test_returnsFalse_whenNeverInstalled() public {
        vm.skip(true);
    }

    /// @notice Returns false when the policy is uninstalled.
    function test_returnsFalse_whenUninstalled() public {
        vm.skip(true);
    }

    /// @notice Returns false when current timestamp is before `validAfter`.
    function test_returnsFalse_whenBeforeValidAfter(uint40 validAfter) public {
        vm.skip(true);

        validAfter;
    }

    /// @notice Returns false when current timestamp is at/after `validUntil`.
    function test_returnsFalse_whenAfterValidUntil(uint40 validUntil) public {
        vm.skip(true);

        validUntil;
    }

    /// @notice Returns true when installed, not uninstalled, and within the validity window.
    function test_returnsTrue_whenWithinValidityWindow() public {
        vm.skip(true);
    }
}

