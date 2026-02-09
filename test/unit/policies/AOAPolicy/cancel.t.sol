// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicyTestBase} from "../../../lib/policies/AOAPolicyTestBase.sol";

/// @title cancelTest
///
/// @notice Test contract for AOA cancel authorization.
contract cancelTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }
}

