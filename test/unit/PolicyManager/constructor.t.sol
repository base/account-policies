// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title constructorTest
///
/// @notice Test contract for `PolicyManager` constructor behavior.
contract constructorTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

