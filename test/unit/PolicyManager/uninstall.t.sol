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
}

