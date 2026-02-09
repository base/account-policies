// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicyTestBase} from "../../../lib/policies/MorphoLoanProtectionPolicyTestBase.sol";

/// @title installTest
///
/// @notice Test contract for Morpho loan protection install/lifecycle constraints.
contract installTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(111);
    }
}

