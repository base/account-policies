// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

/// @title ApprovalResetToken
///
/// @notice ERC-20 mock that requires resetting allowance to zero before setting a new non-zero value (USDT behavior).
contract ApprovalResetToken is ERC20 {
    error ApproveFromNonZeroToNonZero();

    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function approve(address spender, uint256 value) public override returns (bool) {
        if (value != 0 && allowance(msg.sender, spender) != 0) revert ApproveFromNonZeroToNonZero();
        return super.approve(spender, value);
    }
}
