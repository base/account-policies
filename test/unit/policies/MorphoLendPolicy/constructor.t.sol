// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `MorphoLendPolicy` constructor behavior.
contract ConstructorTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(111);
    }
}

