// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLendPolicyTestBase} from "../../../lib/policies/MorphoLendPolicyTestBase.sol";

/// @title getDepositLimitLastUpdatedTest
///
/// @notice Test contract for `MorphoLendPolicy.getDepositLimitLastUpdated`.
contract getDepositLimitLastUpdatedTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(555);
    }
}

