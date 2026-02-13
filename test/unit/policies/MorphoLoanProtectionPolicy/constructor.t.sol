// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title constructorTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` constructor behavior.
contract ConstructorTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase(111);
    }
}

