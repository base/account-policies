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
        setUpMorphoLendBase();
    }

    /// @notice Returns zero usage before any deposits have been made.
    function test_returnsZeroUsage_beforeAnyDeposits() public {
        vm.skip(true);
    }

    /// @notice Returns correct last-updated snapshot after a deposit has been made.
    function test_returnsCorrectLastUpdated_afterDeposit() public {
        vm.skip(true);
    }
}
