// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {RecurringAllowance} from "../../../../src/policies/accounting/RecurringAllowance.sol";

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title GetDepositLimitLastUpdatedTest
///
/// @notice Test contract for `MorphoLendPolicy.getDepositLimitLastUpdated`.
contract GetDepositLimitLastUpdatedTest is MorphoLendPolicyTestBase {
    /// @dev Deposit allowance configured in setUp (1M ether per day).
    uint160 internal constant DEPOSIT_ALLOWANCE = uint160(1_000_000 ether);

    /// @dev Max deposit amount for fuzz runs that must stay within the recurring allowance.
    uint256 internal constant MAX_DEPOSIT = uint256(DEPOSIT_ALLOWANCE);

    function setUp() public {
        setUpMorphoLendBase();
    }

    /// @notice Returns zero usage before any deposits have been made.
    function test_returnsZeroUsage_beforeAnyDeposits() public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        RecurringAllowance.PeriodUsage memory usage = policy.getDepositLimitLastUpdated(policyId);

        assertEq(usage.start, 0);
        assertEq(usage.end, 0);
        assertEq(usage.spend, 0);
    }

    /// @notice Returns correct last-updated snapshot after a deposit has been made.
    ///
    /// @param depositAssets Amount to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_returnsCorrectLastUpdated_afterDeposit(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);
        _execWithNonce(depositAssets, nonce);

        bytes32 policyId = policyManager.getPolicyId(binding);
        RecurringAllowance.PeriodUsage memory usage = policy.getDepositLimitLastUpdated(policyId);

        assertEq(usage.spend, depositAssets);
        assertTrue(usage.end > usage.start);
    }

    /// @notice Returns correct last-updated snapshot after multiple deposits have been made within the same period.
    ///
    /// @param first First deposit amount.
    /// @param second Second deposit amount.
    /// @param nonce1 Nonce for the first execution.
    /// @param nonce2 Nonce for the second execution.
    function test_returnsCorrectLastUpdated_afterMultipleDeposits(
        uint256 first,
        uint256 second,
        uint256 nonce1,
        uint256 nonce2
    ) public {
        vm.assume(nonce1 != nonce2);
        first = bound(first, 1, MAX_DEPOSIT / 2);
        second = bound(second, 1, MAX_DEPOSIT / 2);

        loanToken.mint(address(account), first + second);
        _execWithNonce(first, nonce1);
        _execWithNonce(second, nonce2);

        bytes32 policyId = policyManager.getPolicyId(binding);
        RecurringAllowance.PeriodUsage memory usage = policy.getDepositLimitLastUpdated(policyId);

        assertEq(usage.spend, first + second);
        assertTrue(usage.end > usage.start);
    }
}
