// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title isPolicyUsedTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy.isPolicyUsed`.
contract isPolicyUsedTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(111);
    }
}

