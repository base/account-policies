// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

import {Id, Market, MarketParams, Position} from "../../../../src/interfaces/morpho/BlueTypes.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {MorphoLoanProtectionHarness} from "../../../lib/MorphoLoanProtectionHarness.sol";
import {MockMorphoBlue, MockMorphoOracle} from "../../../lib/mocks/MockMorphoBlue.sol";

/// @title ComputeCurrentLtvTest
///
/// @notice Tests for `MorphoLoanProtectionPolicy._computeCurrentLtv` via test harness.
///
/// @dev Exercises the internal LTV computation directly, covering edge cases that are difficult
///      to reach through the full execute flow (zero borrow shares, zero collateral value,
///      non-1:1 borrow ratios, varied oracle prices).
///
///      Default setUp state:
///        - market: totalBorrowAssets = totalBorrowShares = 1e18 (1:1 borrow ratio)
///        - oracle price: 1e36 (1:1 collateral-to-loan), so collateralValue == collateral
///        - config triggerLtv: 0.7e18 (70%)
contract ComputeCurrentLtvTest is Test {
    uint256 internal constant WAD = 1e18;
    uint256 internal constant ORACLE_PRICE_SCALE = 1e36;

    MorphoLoanProtectionHarness internal harness;
    MockMorphoBlue internal morpho;
    MockMorphoOracle internal oracle;

    Id internal marketId;
    MarketParams internal marketParams;
    address internal testAccount;

    function setUp() public {
        testAccount = makeAddr("testAccount");
        morpho = new MockMorphoBlue();
        oracle = new MockMorphoOracle();
        harness = new MorphoLoanProtectionHarness(address(1), address(this));

        marketId = Id.wrap(bytes32(uint256(1)));
        marketParams = MarketParams({
            loanToken: makeAddr("loanToken"),
            collateralToken: makeAddr("collateralToken"),
            oracle: address(oracle),
            irm: makeAddr("irm"),
            lltv: 0.8e18
        });

        morpho.setMarket(
            marketId,
            marketParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: uint128(1e18),
                totalBorrowShares: uint128(1e18),
                lastUpdate: 0,
                fee: 0
            })
        );

        oracle.setPrice(ORACLE_PRICE_SCALE);
    }

    function _config() internal view returns (MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig memory) {
        return MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
            morpho: address(morpho), marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
        });
    }

    // =============================================================
    // Reverts: zero collateral value
    // =============================================================

    /// @notice Reverts with ZeroCollateralValue when position has zero collateral.
    ///
    /// @param borrowShares Fuzzed borrow shares (revert fires before they matter).
    function test_reverts_whenCollateralIsZero(uint128 borrowShares) public {
        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: borrowShares, collateral: 0})
        );

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroCollateralValue.selector);
        harness.exposed_computeCurrentLtv(_config(), marketParams, testAccount);
    }

    /// @notice Reverts with ZeroCollateralValue when the oracle price is zero.
    ///
    /// @param collateral Fuzzed non-zero collateral.
    /// @param borrowShares Fuzzed borrow shares.
    function test_reverts_whenOraclePriceIsZero(uint128 collateral, uint128 borrowShares) public {
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        oracle.setPrice(0);

        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroCollateralValue.selector);
        harness.exposed_computeCurrentLtv(_config(), marketParams, testAccount);
    }

    /// @notice Reverts with ZeroCollateralValue when collateral * price rounds down to zero.
    ///
    /// @dev Targets the edge where collateral and price are both non-zero but their product is
    ///      less than ORACLE_PRICE_SCALE, causing mulDiv to yield 0.
    ///
    /// @param collateral Small non-zero collateral.
    /// @param price Small non-zero price.
    function test_reverts_whenCollateralValueRoundsToZero(uint128 collateral, uint128 price) public {
        collateral = uint128(bound(collateral, 1, 1e17));
        price = uint128(bound(price, 1, 1e17));
        vm.assume(Math.mulDiv(uint256(collateral), uint256(price), ORACLE_PRICE_SCALE) == 0);

        oracle.setPrice(uint256(price));
        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: uint128(1e18), collateral: collateral})
        );

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroCollateralValue.selector);
        harness.exposed_computeCurrentLtv(_config(), marketParams, testAccount);
    }

    // =============================================================
    // Zero borrow shares branch
    // =============================================================

    /// @notice Returns zero LTV when the market has no outstanding borrows (totalBorrowShares == 0).
    ///
    /// @dev Covers the `totalBorrowShares == 0` branch in `_computeCurrentLtv`.
    ///
    /// @param collateral Fuzzed non-zero collateral.
    /// @param price Fuzzed non-zero oracle price, ensuring collateralValue > 0.
    function test_returnsZero_whenTotalBorrowSharesIsZero(uint128 collateral, uint128 price) public {
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        price = uint128(bound(price, 1, type(uint128).max));
        vm.assume(Math.mulDiv(uint256(collateral), uint256(price), ORACLE_PRICE_SCALE) > 0);

        morpho.setMarket(
            marketId,
            marketParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: 0,
                totalBorrowShares: 0,
                lastUpdate: 0,
                fee: 0
            })
        );

        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: uint128(50e18), collateral: collateral})
        );
        oracle.setPrice(uint256(price));

        uint256 ltv = harness.exposed_computeCurrentLtv(_config(), marketParams, testAccount);
        assertEq(ltv, 0);
    }

    // =============================================================
    // Computation accuracy: 1:1 borrow ratio
    // =============================================================

    /// @notice Computes correct LTV when the borrow ratio is 1:1 (debtAssets == borrowShares).
    ///
    /// @dev With 1:1 ratio: debtAssets == borrowShares.
    ///      LTV = mulDiv(debtAssets, WAD, collateralValue).
    ///
    /// @param borrowShares Fuzzed borrow shares.
    /// @param totalBorrow Fuzzed total borrow (same for assets and shares).
    /// @param collateral Fuzzed collateral.
    /// @param price Fuzzed oracle price.
    function test_computesCorrectLtv_with1to1BorrowRatio(
        uint128 borrowShares,
        uint128 totalBorrow,
        uint128 collateral,
        uint128 price
    ) public {
        totalBorrow = uint128(bound(totalBorrow, 1, type(uint128).max));
        borrowShares = uint128(bound(borrowShares, 0, totalBorrow));
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        price = uint128(bound(price, 1, type(uint128).max));

        uint256 collateralValue = Math.mulDiv(uint256(collateral), uint256(price), ORACLE_PRICE_SCALE);
        vm.assume(collateralValue > 0);

        morpho.setMarket(
            marketId,
            marketParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: totalBorrow,
                totalBorrowShares: totalBorrow,
                lastUpdate: 0,
                fee: 0
            })
        );
        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );
        oracle.setPrice(uint256(price));

        uint256 ltv = harness.exposed_computeCurrentLtv(_config(), marketParams, testAccount);

        uint256 expectedLtv = Math.mulDiv(uint256(borrowShares), WAD, collateralValue);
        assertEq(ltv, expectedLtv);
    }

    // =============================================================
    // Computation accuracy: non-1:1 borrow ratio (interest accrual)
    // =============================================================

    /// @notice Computes correct LTV when borrow ratio diverges from 1:1 (e.g., interest accrual).
    ///
    /// @dev debtAssets = mulDiv(borrowShares, totalBorrowAssets, totalBorrowShares).
    ///      LTV = mulDiv(debtAssets, WAD, collateralValue).
    ///
    /// @param borrowShares Fuzzed borrow shares.
    /// @param totalBorrowAssets Fuzzed total borrow assets.
    /// @param totalBorrowShares Fuzzed total borrow shares.
    /// @param collateral Fuzzed collateral.
    /// @param price Fuzzed oracle price.
    function test_computesCorrectLtv_withNon1to1BorrowRatio(
        uint128 borrowShares,
        uint128 totalBorrowAssets,
        uint128 totalBorrowShares,
        uint128 collateral,
        uint128 price
    ) public {
        totalBorrowShares = uint128(bound(totalBorrowShares, 1, type(uint128).max));
        totalBorrowAssets = uint128(bound(totalBorrowAssets, 1, type(uint128).max));
        borrowShares = uint128(bound(borrowShares, 0, totalBorrowShares));
        collateral = uint128(bound(collateral, 1, type(uint128).max));
        price = uint128(bound(price, 1, type(uint128).max));

        uint256 collateralValue = Math.mulDiv(uint256(collateral), uint256(price), ORACLE_PRICE_SCALE);
        vm.assume(collateralValue > 0);

        morpho.setMarket(
            marketId,
            marketParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: totalBorrowAssets,
                totalBorrowShares: totalBorrowShares,
                lastUpdate: 0,
                fee: 0
            })
        );
        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );
        oracle.setPrice(uint256(price));

        uint256 ltv = harness.exposed_computeCurrentLtv(_config(), marketParams, testAccount);

        uint256 debtAssets = Math.mulDiv(uint256(borrowShares), uint256(totalBorrowAssets), uint256(totalBorrowShares));
        uint256 expectedLtv = Math.mulDiv(debtAssets, WAD, collateralValue);
        assertEq(ltv, expectedLtv);
    }

    // =============================================================
    // _enforceTriggerLtv
    // =============================================================

    /// @notice enforceTriggerLtv does not revert when LTV exactly equals the trigger.
    ///
    /// @dev The guard is `currentLtv < config.triggerLtv`, so equality passes.
    ///      With 1:1 ratio and 1e36 price: LTV = borrowShares * WAD / collateral.
    ///      70 ether * WAD / 100 ether == 0.7e18 exactly.
    function test_enforceTriggerLtv_doesNotRevert_whenLtvEqualsTrigger() public {
        morpho.setPosition(
            marketId,
            testAccount,
            Position({supplyShares: 0, borrowShares: uint128(70 ether), collateral: uint128(100 ether)})
        );

        harness.exposed_enforceTriggerLtv(_config(), marketParams, testAccount);
    }

    /// @notice enforceTriggerLtv does not revert when LTV exceeds the trigger.
    ///
    /// @dev Fuzzed borrowShares with collateral bounded to produce LTV >= triggerLtv.
    ///
    /// @param borrowShares Fuzzed borrow shares.
    /// @param collateral Fuzzed collateral bounded to produce LTV >= triggerLtv.
    function test_enforceTriggerLtv_doesNotRevert_whenLtvExceedsTrigger(uint128 borrowShares, uint128 collateral)
        public
    {
        uint256 triggerLtv = _config().triggerLtv;

        // Bound borrowShares so maxCollateral fits in uint128.
        uint256 maxBorrowShares = (uint256(type(uint128).max) * triggerLtv) / WAD;
        borrowShares = uint128(bound(borrowShares, 1, maxBorrowShares));

        // collateral <= borrowShares * WAD / triggerLtv → LTV >= triggerLtv
        uint256 maxCollateral = (uint256(borrowShares) * WAD) / triggerLtv;
        collateral = uint128(bound(collateral, 1, maxCollateral));

        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );

        harness.exposed_enforceTriggerLtv(_config(), marketParams, testAccount);
    }

    /// @notice enforceTriggerLtv reverts when LTV is below the trigger (healthy position).
    ///
    /// @param borrowShares Fuzzed borrow shares.
    /// @param collateral Fuzzed collateral bounded to produce LTV < triggerLtv.
    function test_enforceTriggerLtv_reverts_whenPositionIsHealthy(uint128 borrowShares, uint128 collateral) public {
        uint256 triggerLtv = _config().triggerLtv;

        // Bound borrowShares so minHealthyCollateral fits in uint128.
        uint256 maxBorrowShares = (uint256(type(uint128).max) * triggerLtv) / WAD;
        borrowShares = uint128(bound(borrowShares, 1, maxBorrowShares));

        // collateral > borrowShares * WAD / triggerLtv → LTV < triggerLtv
        uint256 minHealthyCollateral = (uint256(borrowShares) * WAD) / triggerLtv + 1;
        collateral = uint128(bound(collateral, minHealthyCollateral, type(uint128).max));

        morpho.setPosition(
            marketId, testAccount, Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );

        uint256 expectedLtv = Math.mulDiv(uint256(borrowShares), WAD, uint256(collateral));

        vm.expectRevert(
            abi.encodeWithSelector(MorphoLoanProtectionPolicy.HealthyPosition.selector, expectedLtv, triggerLtv)
        );
        harness.exposed_enforceTriggerLtv(_config(), marketParams, testAccount);
    }
}
