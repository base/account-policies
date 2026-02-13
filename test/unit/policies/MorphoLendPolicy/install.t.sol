// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title installTest
///
/// @notice Test contract for Morpho lend install-time behavior.
contract installTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(333);
    }
}

