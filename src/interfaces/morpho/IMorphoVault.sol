// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title IMorphoVault
///
/// @notice Minimal Morpho vault interface (ERC-4626 style) used by policies in this repo.
interface IMorphoVault {
    /// @notice Returns the underlying asset token for the vault.
    function asset() external view returns (address);

    /// @notice Deposits `assets` and mints vault shares to `receiver`.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
}

