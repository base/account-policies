// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {RecurringAllowance} from "../../../../../src/policies/accounting/RecurringAllowance.sol";
import {RecurringAllowanceHarness} from "../../../../lib/RecurringAllowanceHarness.sol";

/// @title GetCurrentPeriodTest
///
/// @notice Unit tests for `RecurringAllowance.getCurrentPeriod`.
contract GetCurrentPeriodTest is Test {
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
    }

    /// @dev Builds a limit with the default test parameters.
    function _defaultLimit() internal pure returns (RecurringAllowance.Limit memory) {
        return RecurringAllowance.Limit({allowance: ALLOWANCE, period: PERIOD, start: WINDOW_START, end: WINDOW_END});
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when current timestamp is before the allowance window start.
    ///
    /// @param secondsBeforeStart Fuzzed seconds before the window start.
    function test_reverts_whenBeforeStart(uint40 secondsBeforeStart) public {
        secondsBeforeStart = uint40(bound(uint256(secondsBeforeStart), 1, uint256(WINDOW_START)));
        uint40 warpTo = WINDOW_START - secondsBeforeStart;
        vm.warp(warpTo);

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.BeforeStart.selector, warpTo, WINDOW_START));
        harness.getCurrentPeriod(POLICY_ID, _defaultLimit());
    }

    /// @notice Reverts when current timestamp is at or past the allowance window end.
    ///
    /// @param secondsAtOrPastEnd Fuzzed seconds at or past the window end.
    function test_reverts_whenAfterEnd(uint40 secondsAtOrPastEnd) public {
        secondsAtOrPastEnd = uint40(bound(uint256(secondsAtOrPastEnd), 0, uint256(type(uint40).max - WINDOW_END)));
        uint40 warpTo = WINDOW_END + secondsAtOrPastEnd;
        vm.warp(warpTo);

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.AfterEnd.selector, warpTo, WINDOW_END));
        harness.getCurrentPeriod(POLICY_ID, _defaultLimit());
    }

    // =============================================================
    // Fresh period (no prior usage)
    // =============================================================

    /// @notice Returns a fresh period with zero spend when no prior usage exists.
    ///
    /// @param progressIntoPeriod Fuzzed offset into the first period.
    function test_returnsFreshPeriod_whenNoPriorUsage(uint40 progressIntoPeriod) public {
        progressIntoPeriod = uint40(bound(uint256(progressIntoPeriod), 0, uint256(PERIOD) - 1));
        vm.warp(uint256(WINDOW_START) + uint256(progressIntoPeriod));

        RecurringAllowance.PeriodUsage memory usage = harness.getCurrentPeriod(POLICY_ID, _defaultLimit());

        assertEq(usage.start, WINDOW_START);
        assertEq(usage.end, WINDOW_START + PERIOD);
        assertEq(usage.spend, 0);
    }

    /// @notice Period start aligns to the correct multiple of PERIOD from WINDOW_START.
    ///
    /// @param periodIndex Fuzzed period index within the window (0-based).
    /// @param progressPct Fuzzed progress within the period as a percentage (0–99).
    function test_periodStartAlignsToMultiple(uint256 periodIndex, uint256 progressPct) public {
        periodIndex = bound(periodIndex, 0, TOTAL_PERIODS - 1);
        progressPct = bound(progressPct, 0, 99);

        uint256 expectedPeriodStart = uint256(WINDOW_START) + periodIndex * uint256(PERIOD);
        uint256 progressIntoCurrentPeriod = (uint256(PERIOD) * progressPct) / 100;
        vm.warp(expectedPeriodStart + progressIntoCurrentPeriod);

        RecurringAllowance.PeriodUsage memory usage = harness.getCurrentPeriod(POLICY_ID, _defaultLimit());

        assertEq(usage.start, uint40(expectedPeriodStart));
        assertEq(usage.end, uint40(expectedPeriodStart + uint256(PERIOD)));
        assertEq(usage.spend, 0);
    }

    // =============================================================
    // End overflow clamping
    // =============================================================

    /// @notice Clamps period end to limit.end when the final period extends past the window.
    ///
    /// @param tailFraction Fuzzed fraction of PERIOD that forms the trailing partial period (1–99%).
    function test_clampsEndToLimitEnd_whenFinalPeriodIsPartial(uint256 tailFraction) public {
        tailFraction = bound(tailFraction, 1, 99);
        uint40 tailLength = uint40((uint256(PERIOD) * tailFraction) / 100);
        uint40 windowEnd = WINDOW_START + PERIOD + tailLength;

        RecurringAllowance.Limit memory limit =
            RecurringAllowance.Limit({allowance: ALLOWANCE, period: PERIOD, start: WINDOW_START, end: windowEnd});

        uint256 secondPeriodStart = uint256(WINDOW_START) + uint256(PERIOD);
        vm.warp(secondPeriodStart + uint256(tailLength) / 2);

        RecurringAllowance.PeriodUsage memory usage = harness.getCurrentPeriod(POLICY_ID, limit);

        assertEq(usage.start, uint40(secondPeriodStart));
        assertEq(usage.end, windowEnd, "end should be clamped to limit.end");
        assertEq(usage.spend, 0);
    }

    // =============================================================
    // Carry-over of active spend
    // =============================================================

    /// @notice Returns the stored snapshot when still within the same period as a prior spend.
    ///
    /// @param spendAmount Fuzzed initial spend to record.
    /// @param firstProgressPct Fuzzed time into the period for the first spend (0–49%).
    /// @param secondProgressPct Fuzzed time into the period for the query (50–99%).
    function test_returnsStoredSnapshot_whenPeriodStillActive(
        uint160 spendAmount,
        uint256 firstProgressPct,
        uint256 secondProgressPct
    ) public {
        spendAmount = uint160(bound(uint256(spendAmount), 1, ALLOWANCE));
        firstProgressPct = bound(firstProgressPct, 0, 49);
        secondProgressPct = bound(secondProgressPct, 50, 99);

        uint256 firstWarp = uint256(WINDOW_START) + (uint256(PERIOD) * firstProgressPct) / 100;
        uint256 secondWarp = uint256(WINDOW_START) + (uint256(PERIOD) * secondProgressPct) / 100;

        vm.warp(firstWarp);
        harness.useLimit(POLICY_ID, _defaultLimit(), spendAmount);

        vm.warp(secondWarp);
        RecurringAllowance.PeriodUsage memory usage = harness.getCurrentPeriod(POLICY_ID, _defaultLimit());

        assertEq(usage.spend, spendAmount, "should carry over the stored spend");
        assertEq(usage.start, WINDOW_START);
        assertEq(usage.end, WINDOW_START + PERIOD);
    }

    /// @notice Returns a fresh period with zero spend after advancing past the stored period.
    ///
    /// @param spendAmount Fuzzed initial spend to record.
    /// @param extraPeriods Fuzzed number of full periods to skip past the initial one.
    function test_returnsFreshPeriod_whenStoredPeriodExpired(uint160 spendAmount, uint256 extraPeriods) public {
        spendAmount = uint160(bound(uint256(spendAmount), 1, ALLOWANCE));
        extraPeriods = bound(extraPeriods, 1, TOTAL_PERIODS - 2);

        vm.warp(uint256(WINDOW_START) + uint256(PERIOD) / 2);
        harness.useLimit(POLICY_ID, _defaultLimit(), spendAmount);

        uint256 expectedNewPeriodStart = uint256(WINDOW_START) + extraPeriods * uint256(PERIOD);
        vm.warp(expectedNewPeriodStart + uint256(PERIOD) / 4);
        RecurringAllowance.PeriodUsage memory usage = harness.getCurrentPeriod(POLICY_ID, _defaultLimit());

        assertEq(usage.spend, 0, "spend should reset in a new period");
        assertEq(usage.start, uint40(expectedNewPeriodStart));
        assertEq(usage.end, uint40(expectedNewPeriodStart + uint256(PERIOD)));
    }
}
