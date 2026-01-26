// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @dev Minimal vault interface (ERC-4626 style) used by policies.
interface IMorphoVault {
    function asset() external view returns (address);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
}

