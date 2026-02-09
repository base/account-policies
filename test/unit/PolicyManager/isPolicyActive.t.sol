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
}

