// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title IWETH
///
/// @notice Minimal interface for WETH9-compatible wrapped ether contracts.
interface IWETH {
    /// @notice Wrap ETH into WETH. Mints WETH 1:1 for `msg.value`.
    function deposit() external payable;
}
