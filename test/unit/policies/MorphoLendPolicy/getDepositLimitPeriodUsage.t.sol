// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {RecurringAllowance} from "../../../../src/policies/accounting/RecurringAllowance.sol";

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title GetDepositLimitPeriodUsageTest
///
/// @notice Test contract for `MorphoLendPolicy.getDepositLimitPeriodUsage`.
contract GetDepositLimitPeriodUsageTest is MorphoLendPolicyTestBase {
    /// @dev Deposit allowance configured in setUp (1M ether per day).
    uint160 internal constant DEPOSIT_ALLOWANCE = uint160(1_000_000 ether);

    /// @dev Max deposit amount for fuzz runs that must stay within the recurring allowance.
    uint256 internal constant MAX_DEPOSIT = uint256(DEPOSIT_ALLOWANCE);

    function setUp() public {
        setUpMorphoLendBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the supplied config hash does not match the stored config hash.
    ///
    /// @param wrongConfig Arbitrary bytes that do not match the installed config.
    function test_reverts_whenConfigHashMismatch(bytes calldata wrongConfig) public {
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));

        bytes32 policyId = policyManager.getPolicyId(binding);

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        policy.getDepositLimitPeriodUsage(policyId, address(account), wrongConfig);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Returns zero usage before any deposits have been made.
    function test_returnsZeroUsage_beforeAnyDeposits() public {
        bytes32 policyId = policyManager.getPolicyId(binding);

        (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current) =
            policy.getDepositLimitPeriodUsage(policyId, address(account), policyConfig);

        assertEq(lastUpdated.spend, 0);
        assertEq(current.spend, 0);
    }

    /// @notice Returns correct period usage after a deposit has been made.
    ///
    /// @param depositAssets Amount to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_returnsCorrectUsage_afterDeposit(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);
        _execWithNonce(depositAssets, nonce);

        bytes32 policyId = policyManager.getPolicyId(binding);
        (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current) =
            policy.getDepositLimitPeriodUsage(policyId, address(account), policyConfig);

        assertEq(lastUpdated.spend, depositAssets);
        assertEq(current.spend, depositAssets);
    }

    /// @notice Returns correct period usage after multiple deposits have been made within the same period.
    ///
    /// @param first First deposit amount.
    /// @param second Second deposit amount.
    /// @param nonce1 Nonce for the first execution.
    /// @param nonce2 Nonce for the second execution.
    function test_returnsCorrectUsage_afterMultipleDeposits(
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
        (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current) =
            policy.getDepositLimitPeriodUsage(policyId, address(account), policyConfig);

        assertEq(lastUpdated.spend, first + second);
        assertEq(current.spend, first + second);
    }

    /// @notice Returns zero current spend after the deposited period has elapsed and a new period begins.
    ///
    /// @param depositAssets Amount to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_returnsCorrectUsage_afterLastDepositedPeriodPasses(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);
        _execWithNonce(depositAssets, nonce);

        // Warp past the current period (period = 1 day)
        vm.warp(block.timestamp + 1 days);

        bytes32 policyId = policyManager.getPolicyId(binding);
        (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current) =
            policy.getDepositLimitPeriodUsage(policyId, address(account), policyConfig);

        // Stored snapshot retains the deposit from the previous period
        assertEq(lastUpdated.spend, depositAssets);
        // Current period has zero spend (fresh period)
        assertEq(current.spend, 0);
    }
}
