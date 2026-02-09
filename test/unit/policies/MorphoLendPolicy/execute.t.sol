// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLendPolicyTestBase} from "../../../lib/policies/MorphoLendPolicyTestBase.sol";

/// @title executeTest
///
/// @notice Test contract for Morpho lend execution behavior.
contract executeTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(111);
    }
}

