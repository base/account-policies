// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @notice Minimal vault mock for testing `MorphoLendPolicy` (ERC-4626 style).
contract MockMorphoVault {
    address internal immutable _asset;

    constructor(address asset_) {
        _asset = asset_;
    }

    function asset() external view returns (address) {
        return _asset;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        receiver;
        IERC20(_asset).transferFrom(msg.sender, address(this), assets);
        return assets;
    }
}

