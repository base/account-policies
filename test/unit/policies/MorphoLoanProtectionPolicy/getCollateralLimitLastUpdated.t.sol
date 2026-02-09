// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicyTestBase} from "../../../lib/policies/MorphoLoanProtectionPolicyTestBase.sol";

/// @title getCollateralLimitLastUpdatedTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy.getCollateralLimitLastUpdated`.
contract getCollateralLimitLastUpdatedTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(777);
    }
}

