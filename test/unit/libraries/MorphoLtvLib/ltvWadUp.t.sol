// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {SharesMathLib} from "morpho-blue/libraries/SharesMathLib.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

import {MorphoLtvLib} from "../../../../src/libraries/MorphoLtvLib.sol";

import {MorphoLtvLibHarness} from "../../../lib/MorphoLtvLibHarness.sol";

/// @title LtvWadUpTest
///
/// @notice Tests for `MorphoLtvLib.ltvWadUp` and `MorphoLtvLib.collateralValueDown`.
///
/// @dev Pins each conservative rounding step independently: debt rounds up, collateral value rounds down,
///      and the final LTV division rounds up.
contract LtvWadUpTest is Test {
    uint256 internal constant WAD = 1e18;
    uint256 internal constant ORACLE_PRICE_SCALE = 1e36;

    /// @dev Caps borrow totals so `SharesMathLib.toAssetsUp` cannot overflow.
    uint128 internal constant MAX_BORROW_FUZZ = type(uint128).max - 1;

    MorphoLtvLibHarness internal harness;

    function setUp() public {
        harness = new MorphoLtvLibHarness();
    }

    // =============================================================
    // Constants
    // =============================================================

    /// @notice The library scales match Morpho Blue's oracle scale and WAD.
    function test_constants() public pure {
        assertEq(MorphoLtvLib.ORACLE_PRICE_SCALE, ORACLE_PRICE_SCALE);
        assertEq(MorphoLtvLib.WAD, WAD);
    }

    // =============================================================
    // Reverts: zero collateral value
    // =============================================================

    /// @notice Reverts with `ZeroCollateralValue` when the collateral is zero.
    ///
    /// @param borrowShares Fuzzed borrow shares (the revert fires regardless).
    /// @param price Fuzzed oracle price.
    function test_reverts_whenCollateralIsZero(uint128 borrowShares, uint128 price) public {
        vm.expectRevert(MorphoLtvLib.ZeroCollateralValue.selector);
        harness.ltvWadUp({
            borrowShares: borrowShares, totalBorrowAssets: 1e18, totalBorrowShares: 1e18, collateral: 0, price: price
        });
    }

    /// @notice Reverts with `ZeroCollateralValue` when the oracle price is zero.
    ///
    /// @param collateral Fuzzed non-zero collateral.
    function test_reverts_whenPriceIsZero(uint128 collateral) public {
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        vm.expectRevert(MorphoLtvLib.ZeroCollateralValue.selector);
        harness.ltvWadUp({
            borrowShares: 1e18, totalBorrowAssets: 1e18, totalBorrowShares: 1e18, collateral: collateral, price: 0
        });
    }

    /// @notice Reverts with `ZeroCollateralValue` when `collateral * price` rounds down to zero.
    ///
    /// @param collateral Small non-zero collateral.
    /// @param price Small non-zero price.
    function test_reverts_whenCollateralValueRoundsToZero(uint128 collateral, uint128 price) public {
        collateral = uint128(bound(collateral, 1, 1e17));
        price = uint128(bound(price, 1, 1e17));
        vm.assume(uint256(collateral) * uint256(price) < ORACLE_PRICE_SCALE);

        vm.expectRevert(MorphoLtvLib.ZeroCollateralValue.selector);
        harness.ltvWadUp({
            borrowShares: 1e18, totalBorrowAssets: 1e18, totalBorrowShares: 1e18, collateral: collateral, price: price
        });
    }

    // =============================================================
    // Values
    // =============================================================

    /// @notice Returns zero when the position has no borrow shares.
    ///
    /// @param collateral Fuzzed non-zero collateral.
    function test_returnsZero_whenBorrowSharesIsZero(uint128 collateral) public view {
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        assertEq(
            harness.ltvWadUp({
                borrowShares: 0,
                totalBorrowAssets: 0,
                totalBorrowShares: 0,
                collateral: collateral,
                price: ORACLE_PRICE_SCALE
            }),
            0
        );
    }

    /// @notice Matches the reference formula: `ceil(toAssetsUp(shares) * WAD / floor(collateral * price / 1e36))`.
    ///
    /// @param borrowShares Fuzzed borrow shares.
    /// @param totalBorrowAssets Fuzzed total borrow assets.
    /// @param totalBorrowShares Fuzzed total borrow shares.
    /// @param collateral Fuzzed collateral.
    /// @param price Fuzzed oracle price.
    function test_matchesReferenceFormula(
        uint128 borrowShares,
        uint128 totalBorrowAssets,
        uint128 totalBorrowShares,
        uint128 collateral,
        uint128 price
    ) public view {
        totalBorrowShares = uint128(bound(totalBorrowShares, 1, MAX_BORROW_FUZZ));
        totalBorrowAssets = uint128(bound(totalBorrowAssets, 1, MAX_BORROW_FUZZ));
        borrowShares = uint128(bound(borrowShares, 0, totalBorrowShares));
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        price = uint128(bound(price, 1, type(uint128).max));

        uint256 collateralValue = Math.mulDiv(collateral, price, ORACLE_PRICE_SCALE);
        vm.assume(collateralValue > 0);

        uint256 debtAssets = SharesMathLib.toAssetsUp(borrowShares, totalBorrowAssets, totalBorrowShares);
        uint256 expected = Math.mulDiv(debtAssets, WAD, collateralValue, Math.Rounding.Ceil);

        assertEq(
            harness.ltvWadUp({
                borrowShares: borrowShares,
                totalBorrowAssets: totalBorrowAssets,
                totalBorrowShares: totalBorrowShares,
                collateral: collateral,
                price: price
            }),
            expected
        );
    }

    // =============================================================
    // Rounding direction
    // =============================================================

    /// @notice Debt converts from shares rounding up.
    ///
    /// @dev Virtual offsets: 1 share against (assets 2, shares 3) is `ceil(1 * (2 + 1) / (3 + 1e6))` = 1 asset,
    ///      where rounding down would give 0. With collateral value 1e18, the LTV is 1 (not 0).
    function test_roundsDebtUp() public view {
        assertEq(
            harness.ltvWadUp({
                borrowShares: 1, totalBorrowAssets: 2, totalBorrowShares: 3, collateral: 1e18, price: ORACLE_PRICE_SCALE
            }),
            1
        );
    }

    /// @notice Collateral value rounds down.
    ///
    /// @dev `3 * (1e36 / 2) / 1e36` = 1.5, floored to 1.
    function test_collateralValueDown_roundsDown() public view {
        assertEq(harness.collateralValueDown({collateral: 3, price: ORACLE_PRICE_SCALE / 2}), 1);
    }

    /// @notice The final LTV division rounds up.
    ///
    /// @dev Debt 1 against collateral value 3 is `1e18 / 3` = 333...333.33, rounded up to 333...334.
    ///      Uses zero market totals so the one borrow share converts to exactly one asset
    ///      (`ceil(1 * 1 / 1e6)` = 1).
    function test_roundsLtvUp() public view {
        assertEq(
            harness.ltvWadUp({
                borrowShares: 1, totalBorrowAssets: 0, totalBorrowShares: 0, collateral: 3, price: ORACLE_PRICE_SCALE
            }),
            WAD / 3 + 1
        );
    }
}
