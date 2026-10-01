// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {SharesMathLib} from "morpho-blue/libraries/SharesMathLib.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

/// @title MorphoLtvLib
///
/// @notice Shared loan-to-value math for policies that guard Morpho Blue positions.
///
/// @dev Pure functions over raw Morpho values, so callers keep their own state reads (position, market totals,
///      oracle price) and their own copies of the Morpho types. Every rounding step over-estimates the
///      position's risk:
///        - debt: borrow shares converted to assets rounding up (`SharesMathLib.toAssetsUp`);
///        - collateral value: rounded down;
///        - LTV: rounded up.
///      A strict `ltv > cap` guard on the result therefore cannot be slipped under by a 1-wei rounding artifact.
library MorphoLtvLib {
    /// @notice Scale of Morpho Blue oracle prices (1e36).
    uint256 internal constant ORACLE_PRICE_SCALE = 1e36;

    /// @notice Scale of WAD-denominated values (1e18 = 100%).
    uint256 internal constant WAD = 1e18;

    /// @notice Thrown when the collateral prices to zero loan-token units, which would make the LTV undefined.
    error ZeroCollateralValue();

    /// @notice Returns the value of `collateral` in loan-token units, rounded down.
    ///
    /// @param collateral Collateral amount in collateral-token units.
    /// @param price Oracle price of one collateral token quoted in loan tokens, scaled by `ORACLE_PRICE_SCALE`.
    ///
    /// @return collateralValue Collateral value in loan-token units, rounded down.
    function collateralValueDown(uint256 collateral, uint256 price) internal pure returns (uint256 collateralValue) {
        collateralValue = Math.mulDiv(collateral, price, ORACLE_PRICE_SCALE);
    }

    /// @notice Returns a position's LTV in WAD with conservative rounding: debt up, collateral value down, LTV up.
    ///
    /// @dev Does not accrue interest; callers must pass market totals that already reflect accrued interest
    ///      (or accept the understated debt). Reverts with `ZeroCollateralValue` when the collateral value
    ///      rounds down to zero.
    ///
    /// @param borrowShares The position's borrow shares.
    /// @param totalBorrowAssets The market's total borrow assets.
    /// @param totalBorrowShares The market's total borrow shares.
    /// @param collateral The position's collateral in collateral-token units.
    /// @param price Oracle price of one collateral token quoted in loan tokens, scaled by `ORACLE_PRICE_SCALE`.
    ///
    /// @return ltvWad The LTV in WAD (1e18 = 100%), rounded up.
    function ltvWadUp(
        uint256 borrowShares,
        uint256 totalBorrowAssets,
        uint256 totalBorrowShares,
        uint256 collateral,
        uint256 price
    ) internal pure returns (uint256 ltvWad) {
        uint256 debtAssets = SharesMathLib.toAssetsUp(borrowShares, totalBorrowAssets, totalBorrowShares);

        uint256 collateralValue = collateralValueDown(collateral, price);
        if (collateralValue == 0) revert ZeroCollateralValue();

        ltvWad = Math.mulDiv(debtAssets, WAD, collateralValue, Math.Rounding.Ceil);
    }
}
