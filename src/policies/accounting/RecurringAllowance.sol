// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title RecurringAllowance
///
/// @notice Reusable recurring-allowance accounting for policies (SpendPolicy-style).
///
/// @dev Keyed by `policyId` so the manager can remain stateless beyond installed bindings.
library RecurringAllowance {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Allowance bounds for a recurring spend window.
    struct Limit {
        /// @dev Maximum spend per period window.
        uint160 allowance;
        /// @review match uint40?
        /// @dev Period length in seconds.
        uint48 period;
        /// @dev Start timestamp (seconds) inclusive.
        uint48 start;
        /// @dev End timestamp (seconds) exclusive.
        uint48 end;
    }

    /// @notice Stored usage snapshot for a particular active period.
    struct PeriodUsage {
        /// @review match uint40?
        /// @dev Period start timestamp (seconds).
        uint48 start;
        /// @dev Period end timestamp (seconds).
        uint48 end;
        /// @dev Amount spent during the period window.
        uint160 spend;
    }

    /// @notice Storage container for usage snapshots.
    struct State {
        /// @dev Most recent stored usage window per policyId.
        mapping(bytes32 policyId => PeriodUsage) lastUpdated;
    }

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @review natspec?
    error ZeroPeriod();
    error ZeroAllowance();
    error InvalidStartEnd(uint48 start, uint48 end);
    error BeforeStart(uint48 currentTimestamp, uint48 start);
    error AfterEnd(uint48 currentTimestamp, uint48 end);
    error ZeroValue();
    error SpendValueOverflow(uint256 value);
    error ExceededAllowance(uint256 value, uint256 allowance);

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Validates and consumes allowance for `value`, updating stored usage for the current period.
    ///
    /// @param state Allowance state storage.
    /// @param policyId Policy identifier.
    /// @param limit Allowance bounds.
    /// @param value Amount to spend.
    ///
    /// @return current Updated current-period usage.
    function useLimit(State storage state, bytes32 policyId, Limit memory limit, uint256 value)
        internal
        returns (PeriodUsage memory current)
    {
        if (value == 0) revert ZeroValue();
        if (limit.period == 0) revert ZeroPeriod();
        if (limit.allowance == 0) revert ZeroAllowance();
        if (limit.start >= limit.end) revert InvalidStartEnd(limit.start, limit.end);

        current = getCurrentPeriod(state, policyId, limit);
        uint256 totalSpend = value + uint256(current.spend);
        if (totalSpend > type(uint160).max) revert SpendValueOverflow(totalSpend);
        if (totalSpend > limit.allowance) revert ExceededAllowance(totalSpend, limit.allowance);

        // forge-lint: disable-next-line(unsafe-typecast)
        current.spend = uint160(totalSpend);
        state.lastUpdated[policyId] = current;
    }

    /// @notice Return the most recent stored usage window for `policyId`.
    ///
    /// @dev If `spend == 0`, this may represent "no usage yet" (even if other fields are nonzero).
    ///
    /// @param state Allowance state storage.
    /// @param policyId Policy identifier.
    ///
    /// @return Last stored period usage snapshot.
    function getLastUpdated(State storage state, bytes32 policyId) internal view returns (PeriodUsage memory) {
        return state.lastUpdated[policyId];
    }

    /// @notice Compute the current period window and include stored spend if still active.
    ///
    /// @dev Mirrors the period bucketing used by `useLimit`.
    ///
    /// @param state Allowance state storage.
    /// @param policyId Policy identifier.
    /// @param limit Allowance bounds.
    ///
    /// @return Current period usage snapshot (including stored spend if still active).
    function getCurrentPeriod(State storage state, bytes32 policyId, Limit memory limit)
        internal
        view
        returns (PeriodUsage memory)
    {
        uint48 currentTimestamp = uint48(block.timestamp);
        if (currentTimestamp < limit.start) revert BeforeStart(currentTimestamp, limit.start);
        if (currentTimestamp >= limit.end) revert AfterEnd(currentTimestamp, limit.end);

        PeriodUsage memory lastUpdated = state.lastUpdated[policyId];
        bool lastExists = lastUpdated.spend != 0;
        bool lastStillActive = currentTimestamp < lastUpdated.end;
        if (lastExists && lastStillActive) return lastUpdated;

        uint48 currentPeriodProgress = (currentTimestamp - limit.start) % limit.period;
        uint48 start = currentTimestamp - currentPeriodProgress;
        bool endOverflow = uint256(start) + uint256(limit.period) > limit.end;
        uint48 end = endOverflow ? limit.end : start + limit.period;
        return PeriodUsage({start: start, end: end, spend: 0});
    }
}

