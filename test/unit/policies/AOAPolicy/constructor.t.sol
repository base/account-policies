// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `AOAPolicy` constructor behavior.
contract ConstructorTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }
}

