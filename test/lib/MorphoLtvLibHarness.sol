// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLtvLib} from "../../src/libraries/MorphoLtvLib.sol";

/// @title MorphoLtvLibHarness
///
/// @notice Exposes `MorphoLtvLib` internals as external calls so tests can assert reverts.
contract MorphoLtvLibHarness {
    function collateralValueDown(uint256 collateral, uint256 price) external pure returns (uint256) {
        return MorphoLtvLib.collateralValueDown({collateral: collateral, price: price});
    }

    function ltvWadUp(
        uint256 borrowShares,
        uint256 totalBorrowAssets,
        uint256 totalBorrowShares,
        uint256 collateral,
        uint256 price
    ) external pure returns (uint256) {
        return MorphoLtvLib.ltvWadUp({
            borrowShares: borrowShares,
            totalBorrowAssets: totalBorrowAssets,
            totalBorrowShares: totalBorrowShares,
            collateral: collateral,
            price: price
        });
    }
}
