// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicyTestBase} from "../../../lib/policies/MorphoLoanProtectionPolicyTestBase.sol";

/// @title getCollateralLimitPeriodUsageTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy.getCollateralLimitPeriodUsage`.
contract getCollateralLimitPeriodUsageTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(666);
    }
}

