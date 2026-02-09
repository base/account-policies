// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicyTestBase} from "../../../lib/policies/MorphoLoanProtectionPolicyTestBase.sol";

/// @title constructorTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` constructor behavior.
contract constructorTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(111);
    }
}

