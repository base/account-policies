// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title MockMorphoVault
///
/// @notice Minimal ERC-4626-style vault mock for testing `MorphoLendPolicy`.
contract MockMorphoVault {
    /// @notice Underlying asset token.
    address internal immutable _asset;

    /// @notice Constructs the vault.
    ///
    /// @param asset_ Underlying asset token address.
    constructor(address asset_) {
        _asset = asset_;
    }

    /// @notice Returns the underlying asset token.
    function asset() external view returns (address) {
        return _asset;
    }

    /// @notice Deposits `assets` by pulling funds from `msg.sender`.
    ///
    /// @dev This is a minimal test helper; it does not mint meaningful shares.
    ///
    /// @param assets Amount of assets to pull.
    /// @param receiver Share receiver (ignored).
    ///
    /// @return shares Returned as `assets` for convenience.
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        receiver;
        IERC20(_asset).transferFrom(msg.sender, address(this), assets);
        return assets;
    }
}

