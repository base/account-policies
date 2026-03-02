// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {RecurringAllowance} from "../../../../../src/policies/accounting/RecurringAllowance.sol";
import {RecurringAllowanceHarness} from "../../../../lib/RecurringAllowanceHarness.sol";

/// @title GetLastUpdatedTest
///
/// @notice Unit tests for `RecurringAllowance.getLastUpdated`.
contract GetLastUpdatedTest is Test {
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

    /// @notice Returns all-zero fields before any usage has been recorded.
    function test_returnsZero_beforeAnyUsage() public view {
        RecurringAllowance.PeriodUsage memory usage = harness.getLastUpdated(POLICY_ID);
        assertEq(usage.start, 0);
        assertEq(usage.end, 0);
        assertEq(usage.spend, 0);
    }

    /// @notice Returns the stored snapshot after a single spend.
    ///
    /// @param value Fuzzed spend amount within allowance.
    function test_returnsSnapshot_afterSpend(uint160 value) public {
        value = uint160(bound(uint256(value), 1, ALLOWANCE));

        harness.useLimit(POLICY_ID, _defaultLimit(), value);
        RecurringAllowance.PeriodUsage memory usage = harness.getLastUpdated(POLICY_ID);

        assertEq(usage.spend, value);
        assertEq(usage.start, WINDOW_START);
        assertEq(usage.end, WINDOW_START + PERIOD);
    }

    /// @notice Returns the most recent snapshot after spending in a later period.
    ///
    /// @param firstPeriodSpend Amount spent in the first period.
    /// @param secondPeriodSpend Amount spent in a later period.
    /// @param periodsToSkip Number of full periods to advance (at least 1).
    function test_returnsLatestSnapshot_afterPeriodRollover(
        uint160 firstPeriodSpend,
        uint160 secondPeriodSpend,
        uint256 periodsToSkip
    ) public {
        firstPeriodSpend = uint160(bound(uint256(firstPeriodSpend), 1, ALLOWANCE));
        secondPeriodSpend = uint160(bound(uint256(secondPeriodSpend), 1, ALLOWANCE));
        periodsToSkip = bound(periodsToSkip, 1, TOTAL_PERIODS - 2);

        harness.useLimit(POLICY_ID, _defaultLimit(), firstPeriodSpend);

        uint256 laterPeriodStart = uint256(WINDOW_START) + periodsToSkip * uint256(PERIOD);
        vm.warp(laterPeriodStart + uint256(PERIOD) / 4);
        harness.useLimit(POLICY_ID, _defaultLimit(), secondPeriodSpend);

        RecurringAllowance.PeriodUsage memory usage = harness.getLastUpdated(POLICY_ID);

        assertEq(usage.spend, secondPeriodSpend, "should reflect only the latest period spend");
        assertEq(usage.start, uint40(laterPeriodStart));
        assertEq(usage.end, uint40(laterPeriodStart + uint256(PERIOD)));
    }

    /// @notice Calling `getCurrentPeriod` (view) does not mutate the stored snapshot.
    ///
    /// @param value Fuzzed spend amount within allowance.
    function test_unchangedByGetCurrentPeriod(uint160 value) public {
        value = uint160(bound(uint256(value), 1, ALLOWANCE));

        harness.useLimit(POLICY_ID, _defaultLimit(), value);
        RecurringAllowance.PeriodUsage memory snapshotBefore = harness.getLastUpdated(POLICY_ID);

        vm.warp(uint256(WINDOW_START) + uint256(PERIOD) + uint256(PERIOD) / 4);
        harness.getCurrentPeriod(POLICY_ID, _defaultLimit());

        RecurringAllowance.PeriodUsage memory snapshotAfter = harness.getLastUpdated(POLICY_ID);

        assertEq(snapshotAfter.spend, snapshotBefore.spend);
        assertEq(snapshotAfter.start, snapshotBefore.start);
        assertEq(snapshotAfter.end, snapshotBefore.end);
    }
}
