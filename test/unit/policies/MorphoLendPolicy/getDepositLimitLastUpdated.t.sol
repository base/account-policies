// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title GetDepositLimitLastUpdatedTest
///
/// @notice Test contract for `MorphoLendPolicy.getDepositLimitLastUpdated`.
contract GetDepositLimitLastUpdatedTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase(555);
    }
}

