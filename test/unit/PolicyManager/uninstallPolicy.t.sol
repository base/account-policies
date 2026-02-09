// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title uninstallPolicyTest
///
/// @notice Test contract for `PolicyManager.uninstallPolicy`.
contract uninstallPolicyTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

