// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title constructorTest
///
/// @notice Test contract for `MorphoLendPolicy` constructor behavior.
contract constructorTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(111);
    }
}

