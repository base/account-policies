// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {RecurringAllowance} from "../../../../../src/policies/accounting/RecurringAllowance.sol";
import {RecurringAllowanceHarness} from "../../../../lib/RecurringAllowanceHarness.sol";

/// @title UseLimitTest
///
/// @notice Unit tests for `RecurringAllowance.useLimit`.
contract UseLimitTest is Test {
    /// @dev Period length used across tests.
    uint40 internal constant PERIOD = 1 days;
    /// @dev Per-period allowance.
    uint160 internal constant ALLOWANCE = 1000;
    /// @dev Window start timestamp.
    uint40 internal constant WINDOW_START = 100_000;
    /// @dev Number of full periods in the default window.
    uint256 internal constant TOTAL_PERIODS = 100;
    /// @dev Window end, exactly TOTAL_PERIODS * PERIOD after WINDOW_START.
    uint40 internal constant WINDOW_END = WINDOW_START + uint40(TOTAL_PERIODS) * PERIOD;

    bytes32 internal constant POLICY_ID = keccak256("test-policy");

    RecurringAllowanceHarness internal harness;

    function setUp() public {
        harness = new RecurringAllowanceHarness();
        vm.warp(uint256(WINDOW_START) + uint256(PERIOD) / 2);
    }

    /// @dev Builds a valid limit with the default test parameters.
    function _defaultLimit() internal pure returns (RecurringAllowance.Limit memory) {
        return RecurringAllowance.Limit({allowance: ALLOWANCE, period: PERIOD, start: WINDOW_START, end: WINDOW_END});
    }

    // =============================================================
    // Reverts — input validation
    // =============================================================

    /// @notice Reverts when the spend value is zero.
    function test_reverts_whenValueIsZero() public {
        vm.expectRevert(RecurringAllowance.ZeroValue.selector);
        harness.useLimit(POLICY_ID, _defaultLimit(), 0);
    }

    /// @notice Reverts when the period is zero.
    ///
    /// @param value Non-zero spend value.
    function test_reverts_whenPeriodIsZero(uint256 value) public {
        value = bound(value, 1, ALLOWANCE);
        RecurringAllowance.Limit memory limit = _defaultLimit();
        limit.period = 0;
        vm.expectRevert(RecurringAllowance.ZeroPeriod.selector);
        harness.useLimit(POLICY_ID, limit, value);
    }

    /// @notice Reverts when the allowance is zero.
    ///
    /// @param value Non-zero spend value.
    function test_reverts_whenAllowanceIsZero(uint256 value) public {
        value = bound(value, 1, type(uint160).max);
        RecurringAllowance.Limit memory limit = _defaultLimit();
        limit.allowance = 0;
        vm.expectRevert(RecurringAllowance.ZeroAllowance.selector);
        harness.useLimit(POLICY_ID, limit, value);
    }

    /// @notice Reverts when `start >= end`.
    ///
    /// @param start Fuzzed start timestamp.
    /// @param end Fuzzed end timestamp such that `start >= end`.
    function test_reverts_whenStartGteEnd(uint40 start, uint40 end) public {
        end = uint40(bound(uint256(end), 0, type(uint40).max - 1));
        start = uint40(bound(uint256(start), uint256(end), type(uint40).max));

        RecurringAllowance.Limit memory limit = _defaultLimit();
        limit.start = start;
        limit.end = end;

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.InvalidStartEnd.selector, start, end));
        harness.useLimit(POLICY_ID, limit, 1);
    }

    // =============================================================
    // Reverts — exceeds allowance
    // =============================================================

    /// @notice Reverts when a single spend exceeds the allowance.
    ///
    /// @param excess Fuzzed amount above the allowance.
    function test_reverts_whenSingleSpendExceedsAllowance(uint256 excess) public {
        excess = bound(excess, 1, type(uint96).max);
        uint256 value = uint256(ALLOWANCE) + excess;

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, value, ALLOWANCE));
        harness.useLimit(POLICY_ID, _defaultLimit(), value);
    }

    /// @notice Reverts when cumulative spend within a period exceeds the allowance.
    ///
    /// @param firstSpend First spend (leaves at least 1 unit of remaining capacity).
    function test_reverts_whenCumulativeSpendExceedsAllowance(uint160 firstSpend) public {
        firstSpend = uint160(bound(uint256(firstSpend), 1, ALLOWANCE - 1));
        harness.useLimit(POLICY_ID, _defaultLimit(), firstSpend);

        uint256 remaining = uint256(ALLOWANCE) - uint256(firstSpend);
        uint256 overflowAmount = remaining + 1;
        uint256 totalAfterOverflow = uint256(firstSpend) + overflowAmount;

        vm.expectRevert(
            abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, totalAfterOverflow, ALLOWANCE)
        );
        harness.useLimit(POLICY_ID, _defaultLimit(), overflowAmount);
    }

    // =============================================================
    // Success — happy path
    // =============================================================

    /// @notice Consumes allowance and returns correct period usage on first spend.
    ///
    /// @param value Fuzzed spend amount within allowance.
    function test_consumesAllowance_onFirstSpend(uint160 value) public {
        value = uint160(bound(uint256(value), 1, ALLOWANCE));

        RecurringAllowance.PeriodUsage memory usage = harness.useLimit(POLICY_ID, _defaultLimit(), value);

        assertEq(usage.spend, value);
        assertEq(usage.start, WINDOW_START);
        assertEq(usage.end, WINDOW_START + PERIOD);
    }

    /// @notice Updates stored state so `getLastUpdated` reflects the spend.
    ///
    /// @param value Fuzzed spend amount within allowance.
    function test_updatesStorage_afterSpend(uint160 value) public {
        value = uint160(bound(uint256(value), 1, ALLOWANCE));

        harness.useLimit(POLICY_ID, _defaultLimit(), value);
        RecurringAllowance.PeriodUsage memory stored = harness.getLastUpdated(POLICY_ID);

        assertEq(stored.spend, value);
        assertEq(stored.start, WINDOW_START);
        assertEq(stored.end, WINDOW_START + PERIOD);
    }

    /// @notice Accumulates spend across multiple calls within the same period.
    ///
    /// @param firstSpend First spend amount (up to half the allowance).
    /// @param secondSpend Second spend amount (up to half the allowance).
    function test_accumulatesSpend_withinSamePeriod(uint160 firstSpend, uint160 secondSpend) public {
        firstSpend = uint160(bound(uint256(firstSpend), 1, ALLOWANCE / 2));
        secondSpend = uint160(bound(uint256(secondSpend), 1, ALLOWANCE / 2));

        harness.useLimit(POLICY_ID, _defaultLimit(), firstSpend);
        RecurringAllowance.PeriodUsage memory usage = harness.useLimit(POLICY_ID, _defaultLimit(), secondSpend);

        assertEq(usage.spend, uint256(firstSpend) + uint256(secondSpend));
    }

    /// @notice Allows spending the exact full allowance in a single call.
    function test_allowsExactFullAllowance() public {
        RecurringAllowance.PeriodUsage memory usage = harness.useLimit(POLICY_ID, _defaultLimit(), ALLOWANCE);

        assertEq(usage.spend, ALLOWANCE);
    }

    // =============================================================
    // Period rollover
    // =============================================================

    /// @notice Resets spend after rolling into a fresh period.
    ///
    /// @param firstPeriodSpend Amount spent in the first period.
    /// @param secondPeriodSpend Amount spent in the second period.
    /// @param periodsToSkip Number of full periods to advance past the initial one (at least 1).
    function test_resetsSpend_afterPeriodRollover(
        uint160 firstPeriodSpend,
        uint160 secondPeriodSpend,
        uint256 periodsToSkip
    ) public {
        firstPeriodSpend = uint160(bound(uint256(firstPeriodSpend), 1, ALLOWANCE));
        secondPeriodSpend = uint160(bound(uint256(secondPeriodSpend), 1, ALLOWANCE));
        periodsToSkip = bound(periodsToSkip, 1, TOTAL_PERIODS - 2);

        harness.useLimit(POLICY_ID, _defaultLimit(), firstPeriodSpend);

        uint256 newPeriodStart = uint256(WINDOW_START) + periodsToSkip * uint256(PERIOD);
        vm.warp(newPeriodStart + uint256(PERIOD) / 4);
        RecurringAllowance.PeriodUsage memory usage = harness.useLimit(POLICY_ID, _defaultLimit(), secondPeriodSpend);

        assertEq(usage.spend, secondPeriodSpend, "spend should only reflect the new period");
        assertEq(usage.start, uint40(newPeriodStart));
        assertEq(usage.end, uint40(newPeriodStart + uint256(PERIOD)));
    }

    // =============================================================
    // Isolation across policyIds
    // =============================================================

    /// @notice Spend on one policyId does not affect a different policyId.
    ///
    /// @param value Fuzzed spend amount.
    function test_isolatesSpend_acrossPolicyIds(uint160 value) public {
        value = uint160(bound(uint256(value), 1, ALLOWANCE));
        bytes32 otherPolicyId = keccak256("other-policy");

        harness.useLimit(POLICY_ID, _defaultLimit(), value);

        RecurringAllowance.PeriodUsage memory otherUsage = harness.getCurrentPeriod(otherPolicyId, _defaultLimit());
        assertEq(otherUsage.spend, 0, "other policyId should have zero spend");
    }
}
