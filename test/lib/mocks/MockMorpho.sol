// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title MockMorphoVault
///
/// @notice Minimal ERC-4626-style vault mock for testing `MorphoLendPolicy`.
contract MockMorphoVault {
    address internal immutable _ASSET;

    constructor(address asset_) {
        _ASSET = asset_;
    }

    function asset() external view returns (address) {
        return _ASSET;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        receiver;
        IERC20(_ASSET).transferFrom(msg.sender, address(this), assets);
        return assets;
    }
}

