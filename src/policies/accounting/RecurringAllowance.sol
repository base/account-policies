// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Reusable recurring-allowance accounting (SpendPolicy-style) for policies.
/// @dev Keyed by `policyId` so the manager can remain stateless beyond installed bindings.
library RecurringAllowance {
    struct Limit {
        uint160 allowance;
        uint48 period;
        uint48 start;
        uint48 end;
    }

    struct PeriodUsage {
        uint48 start;
        uint48 end;
        uint160 spend;
    }

    struct State {
        mapping(bytes32 policyId => PeriodUsage) lastUpdated;
    }

    error ZeroPeriod();
    error ZeroAllowance();
    error InvalidStartEnd(uint48 start, uint48 end);
    error BeforeStart(uint48 currentTimestamp, uint48 start);
    error AfterEnd(uint48 currentTimestamp, uint48 end);
    error ZeroValue();
    error SpendValueOverflow(uint256 value);
    error ExceededAllowance(uint256 value, uint256 allowance);

    function useLimit(State storage state, bytes32 policyId, Limit memory limit, uint256 value)
        internal
        returns (PeriodUsage memory current)
    {
        if (value == 0) revert ZeroValue();
        if (limit.period == 0) revert ZeroPeriod();
        if (limit.allowance == 0) revert ZeroAllowance();
        if (limit.start >= limit.end) revert InvalidStartEnd(limit.start, limit.end);

        current = _getCurrentPeriod(state, policyId, limit);
        uint256 totalSpend = value + uint256(current.spend);
        if (totalSpend > type(uint160).max) revert SpendValueOverflow(totalSpend);
        if (totalSpend > limit.allowance) revert ExceededAllowance(totalSpend, limit.allowance);

        // forge-lint: disable-next-line(unsafe-typecast)
        current.spend = uint160(totalSpend);
        state.lastUpdated[policyId] = current;
    }

    function _getCurrentPeriod(State storage state, bytes32 policyId, Limit memory limit)
        private
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

