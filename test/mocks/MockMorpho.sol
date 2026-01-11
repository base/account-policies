// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {MarketParams} from "../../src/policies/LendingPolicy.sol";

/// @notice Minimal Morpho mock for testing `LendingPolicy`.
contract MockMorpho {
    function supply(MarketParams calldata marketParams, uint256 assets, uint256, address onBehalf, bytes calldata)
        external
        returns (uint256 assetsSupplied, uint256 sharesSupplied)
    {
        onBehalf;
        IERC20(marketParams.loanToken).transferFrom(msg.sender, address(this), assets);
        return (assets, assets);
    }
}

