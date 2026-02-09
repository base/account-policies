// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicyTestBase} from "../../../lib/policies/AOAPolicyTestBase.sol";

/// @title pauseTest
///
/// @notice Test contract for `AOAPolicy.pause`.
contract pauseTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }
}

