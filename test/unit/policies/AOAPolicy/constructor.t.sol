// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicyTestBase} from "../../../lib/policies/AOAPolicyTestBase.sol";

/// @title constructorTest
///
/// @notice Test contract for `AOAPolicy` constructor behavior.
contract constructorTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }
}

