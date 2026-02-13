// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title RevertingReceiver
///
/// @notice Test-only call target that always reverts.
///
/// @dev Used to assert that `PolicyManager` bubbles reverts from the account call path.
contract RevertingReceiver {
    /// @notice Thrown on every `ping`.
    error ReceiverReverted();

    /// @notice Always reverts (and is payable to allow value-forwarding tests).
    function ping() external payable {
        revert ReceiverReverted();
    }
}

