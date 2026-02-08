// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title CallReceiver
///
/// @notice Minimal call target used by `PolicyManager` tests to assert wallet execution occurred.
contract CallReceiver {
    uint256 public calls;
    bytes32 public lastTag;
    address public lastCaller;

    function ping(bytes32 tag) external payable {
        calls++;
        lastTag = tag;
        lastCaller = msg.sender;
    }
}

