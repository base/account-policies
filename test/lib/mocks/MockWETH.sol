// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

/// @title MockWETH
///
/// @notice Minimal WETH9-compatible mock for unit tests. Wraps ETH into ERC-20 WETH 1:1.
contract MockWETH is ERC20 {
    constructor() ERC20("Wrapped Ether", "WETH") {}

    /// @notice Wrap ETH into WETH. Mints WETH 1:1 for `msg.value`.
    function deposit() external payable {
        _mint(msg.sender, msg.value);
    }

    /// @notice Unwrap WETH into ETH. Burns WETH and sends ETH 1:1.
    function withdraw(uint256 amount) external {
        _burn(msg.sender, amount);
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "ETH transfer failed");
    }

    /// @notice Accept plain ETH transfers (equivalent to deposit).
    receive() external payable {
        _mint(msg.sender, msg.value);
    }
}
