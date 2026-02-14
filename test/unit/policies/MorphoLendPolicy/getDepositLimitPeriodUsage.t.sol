// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title GetDepositLimitPeriodUsageTest
///
/// @notice Test contract for `MorphoLendPolicy.getDepositLimitPeriodUsage`.
contract GetDepositLimitPeriodUsageTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the supplied config hash does not match the stored config hash.
    function test_reverts_whenConfigHashMismatch() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Returns zero usage before any deposits have been made.
    function test_returnsZeroUsage_beforeAnyDeposits() public {
        vm.skip(true);
    }

    /// @notice Returns correct period usage after a deposit has been made.
    function test_returnsCorrectUsage_afterDeposit() public {
        vm.skip(true);
    }
}
