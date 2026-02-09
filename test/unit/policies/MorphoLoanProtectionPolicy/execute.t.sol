// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicyTestBase} from "../../../lib/policies/MorphoLoanProtectionPolicyTestBase.sol";

/// @title executeTest
///
/// @notice Test contract for Morpho loan protection execution behavior.
contract executeTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(111);
    }
}

