// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {SharesMathLib} from "morpho-blue/libraries/SharesMathLib.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {Id, Market, MarketParams, Position} from "../../../../src/interfaces/morpho/BlueTypes.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";
import {ApprovalResetToken} from "../../../lib/mocks/ApprovalResetToken.sol";
import {MockMorphoBlue, MockMorphoOracle} from "../../../lib/mocks/MockMorphoBlue.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` execution behavior (`_onSingleExecutorExecute`).
///
/// @dev SingleExecutor-inherited execute behavior (pause gate, executor sig, nonce replay, deadline) is covered
///      in `test/unit/policies/SingleExecutorAuthorizedPolicy/execute.t.sol`. This suite covers
///      MorphoLoanProtectionPolicy-specific execution logic only.
///
///      Default setUp state:
///        - position: borrowShares=75e18, collateral=100e18 (1:1 borrow ratio → debtAssets=75e18)
///        - oracle price: 1e36 (1:1 collateral-to-loan)
///        - currentLtv: 75% (0.75e18)
///        - triggerLtv: 70% (0.7e18) → position is unhealthy, execution allowed
///        - maxTopUpAssets: 25 ether
contract ExecuteTest is MorphoLoanProtectionPolicyTestBase {
    /// @dev Max collateral top-up allowed by the setUp config.
    uint256 internal constant MAX_TOP_UP = 25 ether;

    /// @dev Trigger LTV threshold from the setUp config (0.7e18 = 70%).
    uint256 internal constant TRIGGER_LTV = 0.7e18;

    /// @dev Debt assets derived from the setUp position (borrowShares=75e18, 1:1 borrow ratio).
    uint256 internal constant DEBT_ASSETS = 75 ether;

    /// @dev WAD scaling factor (1e18 = 100%) used for LTV arithmetic.
    uint256 internal constant WAD = 1e18;

    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policy has already been executed (one-shot).
    ///
    /// @param topUpAssets Amount for both executions.
    /// @param nonce1 Nonce for the first (successful) execution.
    /// @param nonce2 Nonce for the second (reverted) execution.
    function test_reverts_whenPolicyAlreadyUsed(uint256 topUpAssets, uint256 nonce1, uint256 nonce2) public {
        vm.assume(nonce1 != nonce2);
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        _exec(topUpAssets, nonce1);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce2, 0);

        vm.expectRevert(abi.encodeWithSelector(MorphoLoanProtectionPolicy.PolicyAlreadyUsed.selector, policyId));
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the top-up amount is zero.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenTopUpAmountIsZero(uint256 nonce) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(0, nonce, 0);

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroAmount.selector);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the top-up amount exceeds the configured maximum.
    ///
    /// @param topUpAssets Amount exceeding maxTopUpAssets.
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenTopUpExceedsMax(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, MAX_TOP_UP + 1, type(uint256).max);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(MorphoLoanProtectionPolicy.TopUpAboveMax.selector, topUpAssets, MAX_TOP_UP)
        );
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the top-up is insufficient to bring the position's LTV below the market's LLTV,
    ///         and preserves the one-shot (policy is NOT consumed).
    ///
    /// @dev Moves the position into the liquidation zone (LTV > LLTV), then attempts a small top-up that
    ///      reduces LTV but not enough to cross below LLTV. The `_onPostExecute` hook detects this and
    ///      reverts the entire transaction atomically — the one-shot is preserved so the executor can retry
    ///      with a larger amount.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenTopUpInsufficientToBringLtvBelowLltv(uint256 nonce) public {
        // Push position into liquidation zone: borrowShares=85e18, collateral=100e18 → LTV ≈ 85% > LLTV=80%.
        morpho.setPosition(
            marketId,
            address(account),
            Position({supplyShares: 0, borrowShares: uint128(85 ether), collateral: uint128(100 ether)})
        );

        // Top up 5 ether → new collateral = 105e18 → post-LTV ≈ 80.95% (still ≥ LLTV=80%).
        uint256 topUpAssets = 5 ether;

        // Compute expected post-top-up LTV to match the revert args.
        uint256 debtAssets = SharesMathLib.toAssetsUp(85 ether, 1e18, 1e18);
        uint256 postCollateral = 100 ether + topUpAssets;
        uint256 expectedPostLtv = Math.mulDiv(debtAssets, WAD, postCollateral);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(
                MorphoLoanProtectionPolicy.PostTopUpLtvAboveLltv.selector, expectedPostLtv, marketParams.lltv
            )
        );
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        // Atomicity: one-shot must NOT be consumed since the entire transaction reverted.
        assertFalse(policy.isPolicyUsed(policyId));
    }

    /// @notice Reverts when the account's position LTV is below the trigger threshold (position is healthy).
    ///
    /// @dev The setUp market has a 1:1 borrow share ratio (totalBorrowAssets == totalBorrowShares = 1e18).
    ///      With virtual shares, debtAssets = mulDiv(borrowShares, totalBorrow + 1, totalBorrow + 1e6, Ceil).
    ///      The oracle price is 1e36, so collateralValue == collateral.
    ///
    /// @param topUpAssets Valid top-up amount (revert fires before it matters).
    /// @param nonce Executor-chosen nonce.
    /// @param borrowShares Fuzzed borrow shares.
    /// @param collateral Fuzzed collateral, bounded above the minimum healthy threshold.
    function test_reverts_whenPositionIsHealthy(
        uint256 topUpAssets,
        uint256 nonce,
        uint128 borrowShares,
        uint128 collateral
    ) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);
        uint256 totalBorrow = 1e18;

        uint256 maxBorrowShares = (uint256(type(uint128).max) * TRIGGER_LTV) / WAD;
        borrowShares = uint128(bound(borrowShares, 1, maxBorrowShares));

        uint256 debtAssets = SharesMathLib.toAssetsUp(uint256(borrowShares), totalBorrow, totalBorrow);
        uint256 minHealthyCollateral = (debtAssets * WAD) / TRIGGER_LTV + 1;
        collateral = uint128(bound(collateral, minHealthyCollateral, type(uint128).max));

        morpho.setPosition(
            marketId, address(account), Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );

        uint256 expectedLtv = Math.mulDiv(debtAssets, WAD, uint256(collateral));

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(MorphoLoanProtectionPolicy.HealthyPosition.selector, expectedLtv, TRIGGER_LTV)
        );
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Supplies collateral to the Morpho Blue market on behalf of the account.
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_suppliesCollateralToMorpho(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        uint256 morphoBalanceBefore = collateralToken.balanceOf(address(morpho));
        uint256 accountBalanceBefore = collateralToken.balanceOf(address(account));

        _exec(topUpAssets, nonce);

        assertEq(collateralToken.balanceOf(address(morpho)), morphoBalanceBefore + topUpAssets);
        assertEq(collateralToken.balanceOf(address(account)), accountBalanceBefore - topUpAssets);
    }

    /// @notice Approves the collateral token before calling supplyCollateral.
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_approvesCollateralBeforeSupply(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0);

        vm.expectEmit(true, true, true, true, address(collateralToken));
        emit IERC20.Approval(address(account), address(morpho), topUpAssets);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Marks the policy instance as used after execution (one-shot).
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_marksPolicyAsUsed(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        bytes32 policyId = policyManager.getPolicyId(binding);
        assertFalse(policy.isPolicyUsed(policyId));

        _exec(topUpAssets, nonce);

        assertTrue(policy.isPolicyUsed(policyId));
    }

    /// @notice Emits PolicyExecuted on successful execution.
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_emitsPolicyExecuted(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyExecuted(policyId, address(account), address(policy), keccak256(executionData));
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    // =============================================================
    // Helpers
    // =============================================================

    function _exec(uint256 topUp, uint256 nonce) internal {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUp, nonce, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Top-up succeeds when the collateral token requires approval reset (e.g. USDT).
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_topsUpCollateral_whenAssetRequiresApprovalReset(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        // Deploy USDT-like token as collateral
        ApprovalResetToken resetCollateral = new ApprovalResetToken("ResetCollateral", "RSTC");

        // Set up new market with reset token as collateral
        MockMorphoOracle resetOracle = new MockMorphoOracle();
        resetOracle.setPrice(1e36);

        Id newMarketId = Id.wrap(bytes32(uint256(456)));
        MarketParams memory newMarketParams = MarketParams({
            loanToken: address(loanToken),
            collateralToken: address(resetCollateral),
            oracle: address(resetOracle),
            irm: address(0xBEEF),
            lltv: 0.8e18
        });

        morpho.setMarket(
            newMarketId,
            newMarketParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: uint128(1e18),
                totalBorrowShares: uint128(1e18),
                lastUpdate: uint128(block.timestamp),
                fee: 0
            })
        );

        // Set account position in the new market (same as setUp: borrowShares=75e18, collateral=100e18)
        morpho.setPosition(
            newMarketId,
            address(account),
            Position({supplyShares: 0, borrowShares: uint128(75 ether), collateral: uint128(100 ether)})
        );

        // Create new policy binding with reset token market
        bytes memory newPolicyConfig = abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor}),
            abi.encode(
                MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                    marketId: newMarketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
                })
            )
        );

        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 1, // Different salt
            policyConfig: newPolicyConfig
        });

        bytes memory userSig = _signInstall(newBinding);
        policyManager.installWithSignature(newBinding, userSig, 0, bytes(""));

        // Mint reset token to account
        resetCollateral.mint(address(account), topUpAssets);

        // Set non-zero allowance from account to morpho (simulating previous approval)
        vm.prank(address(account));
        resetCollateral.approve(address(morpho), 1);

        // Verify allowance is set
        assertEq(resetCollateral.allowance(address(account), address(morpho)), 1);

        // Execute should succeed (policy zeros the allowance first, then approves the amount)
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory executionData = _encodePolicyDataLocal(newBinding, newPolicyConfig, topUpAssets, nonce, 0);

        uint256 morphoBalanceBefore = resetCollateral.balanceOf(address(morpho));
        uint256 accountBalanceBefore = resetCollateral.balanceOf(address(account));

        policyManager.execute(address(policy), newPolicyId, newPolicyConfig, executionData);

        assertEq(resetCollateral.balanceOf(address(morpho)), morphoBalanceBefore + topUpAssets);
        assertEq(resetCollateral.balanceOf(address(account)), accountBalanceBefore - topUpAssets);
    }
}
