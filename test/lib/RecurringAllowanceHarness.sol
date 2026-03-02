// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {RecurringAllowance} from "../../src/policies/accounting/RecurringAllowance.sol";

/// @title RecurringAllowanceHarness
///
/// @notice Exposes `RecurringAllowance` library internals for direct unit testing.
contract RecurringAllowanceHarness {
    using RecurringAllowance for RecurringAllowance.State;

    RecurringAllowance.State internal _state;

    function useLimit(bytes32 policyId, RecurringAllowance.Limit memory limit, uint256 value)
        external
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return _state.useLimit(policyId, limit, value);
    }

    function getCurrentPeriod(bytes32 policyId, RecurringAllowance.Limit memory limit)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return _state.getCurrentPeriod(policyId, limit);
    }

    function getLastUpdated(bytes32 policyId) external view returns (RecurringAllowance.PeriodUsage memory) {
        return _state.getLastUpdated(policyId);
    }
}
