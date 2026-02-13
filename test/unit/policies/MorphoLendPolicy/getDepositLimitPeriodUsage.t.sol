// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title getDepositLimitPeriodUsageTest
///
/// @notice Test contract for `MorphoLendPolicy.getDepositLimitPeriodUsage`.
contract GetDepositLimitPeriodUsageTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(222);
    }
}

