// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Minimal ERC20-like token whose `transfer` always returns `false` without reverting.
///
/// @dev Used to test that `TransferSettingsPolicy._onPostExecute` catches non-standard tokens
///      that silently fail their transfers (e.g. USDT-mainnet style). Balances are never updated.
contract FalseReturningERC20 {
    mapping(address account => uint256 balance) public balanceOf;

    /// @notice Mints `amount` tokens to `to` for test setup.
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    /// @notice Always returns `false` without reverting or moving tokens.
    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    /// @notice Always returns `false` without reverting or moving tokens.
    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}
