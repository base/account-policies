// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {Position} from "../../../../src/interfaces/morpho/BlueTypes.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` execution behavior (`_onAOAExecute`).
///
/// @dev AOA-inherited execute behavior (pause gate, executor sig, nonce replay, deadline) is covered
///      in `test/unit/policies/AOAPolicy/execute.t.sol`. This suite covers
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

    /// @notice Reverts when the account's position LTV is below the trigger threshold (position is healthy).
    ///
    /// @dev The setUp market has a 1:1 borrow share ratio (totalBorrowAssets == totalBorrowShares),
    ///      so debtAssets == borrowShares. The oracle price is 1e36, so collateralValue == collateral.
    ///      Therefore: LTV = borrowShares * WAD / collateral.
    ///      Healthy when: collateral > borrowShares * WAD / triggerLtv.
    ///
    /// @param topUpAssets Valid top-up amount (revert fires before it matters).
    /// @param nonce Executor-chosen nonce.
    /// @param borrowShares Fuzzed borrow shares (equals debt assets in the setUp's 1:1 market).
    /// @param collateral Fuzzed collateral, bounded above the minimum healthy threshold.
    function test_reverts_whenPositionIsHealthy(
        uint256 topUpAssets,
        uint256 nonce,
        uint128 borrowShares,
        uint128 collateral
    ) public {
        topUpAssets = bound(topUpAssets, 1, MAX_TOP_UP);

        // Bound borrowShares so the minimum healthy collateral fits in uint128.
        uint256 maxBorrowShares = (uint256(type(uint128).max) * TRIGGER_LTV) / WAD;
        borrowShares = uint128(bound(borrowShares, 1, maxBorrowShares));

        // Derive the minimum collateral that makes LTV strictly below triggerLtv.
        uint256 minHealthyCollateral = (uint256(borrowShares) * WAD) / TRIGGER_LTV + 1;
        collateral = uint128(bound(collateral, minHealthyCollateral, type(uint128).max));

        morpho.setPosition(
            marketId, address(account), Position({supplyShares: 0, borrowShares: borrowShares, collateral: collateral})
        );

        uint256 expectedLtv = (uint256(borrowShares) * WAD) / uint256(collateral);

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
}
