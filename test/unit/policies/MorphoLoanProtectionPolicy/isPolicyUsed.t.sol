// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title IsPolicyUsedTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy.isPolicyUsed`.
contract IsPolicyUsedTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    /// @notice Returns false for a policy that has not been executed.
    function test_returnsFalse_beforeExecution() public {
        vm.skip(true);
    }

    /// @notice Returns true for a policy that has been executed.
    function test_returnsTrue_afterExecution() public {
        vm.skip(true);
    }
}
