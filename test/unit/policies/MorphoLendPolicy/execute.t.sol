// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../../../../src/policies/MorphoLendPolicy.sol";
import {RecurringAllowance} from "../../../../src/policies/accounting/RecurringAllowance.sol";

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `MorphoLendPolicy` execution behavior (`_onAOAExecute`).
///
/// @dev AOA-inherited execute behavior (pause gate, executor sig, nonce replay, deadline) is covered
///      in `test/unit/policies/AOAPolicy/execute.t.sol`. This suite covers MorphoLendPolicy-specific
///      execution logic only.
contract ExecuteTest is MorphoLendPolicyTestBase {
    /// @dev Deposit allowance configured in setUp (1M ether per day).
    uint160 internal constant DEPOSIT_ALLOWANCE = uint160(1_000_000 ether);

    /// @dev Max deposit amount for fuzz runs that must stay within the recurring allowance.
    uint256 internal constant MAX_DEPOSIT = uint256(DEPOSIT_ALLOWANCE);

    function setUp() public {
        setUpMorphoLendBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the deposit amount is zero.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenDepositAmountIsZero(uint256 nonce) public {
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({depositAssets: 0});
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyDataWithSig(binding, ld, nonce, 0);

        vm.expectRevert(MorphoLendPolicy.ZeroAmount.selector);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the deposit exceeds the recurring allowance for the current period.
    ///
    /// @param depositAssets Amount that exceeds the configured allowance.
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenExceedsAllowance(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, uint256(DEPOSIT_ALLOWANCE) + 1, type(uint160).max);

        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({depositAssets: depositAssets});
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyDataWithSig(binding, ld, nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, depositAssets, DEPOSIT_ALLOWANCE)
        );
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Deposits assets into the Morpho vault on behalf of the account.
    ///
    /// @param depositAssets Amount of underlying assets to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_depositsIntoVault(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);

        uint256 vaultBalanceBefore = loanToken.balanceOf(address(vault));
        uint256 accountBalanceBefore = loanToken.balanceOf(address(account));

        _execWithNonce(depositAssets, nonce);

        assertEq(loanToken.balanceOf(address(vault)), vaultBalanceBefore + depositAssets);
        assertEq(loanToken.balanceOf(address(account)), accountBalanceBefore - depositAssets);
    }

    /// @notice Approves the vault to spend the deposit token before calling deposit.
    ///
    /// @param depositAssets Amount of underlying assets to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_approvesVaultBeforeDeposit(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);

        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({depositAssets: depositAssets});
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyDataWithSig(binding, ld, nonce, 0);

        vm.expectEmit(true, true, true, true, address(loanToken));
        emit IERC20.Approval(address(account), address(vault), depositAssets);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Updates the recurring allowance usage after a successful deposit.
    ///
    /// @param depositAssets Amount of underlying assets to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_updatesAllowanceUsage(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);

        bytes32 policyId = policyManager.getPolicyId(binding);

        RecurringAllowance.PeriodUsage memory usageBefore = policy.getDepositLimitLastUpdated(policyId);
        assertEq(usageBefore.spend, 0);

        _execWithNonce(depositAssets, nonce);

        RecurringAllowance.PeriodUsage memory usageAfter = policy.getDepositLimitLastUpdated(policyId);
        assertEq(usageAfter.spend, depositAssets);
    }

    /// @notice Emits PolicyExecuted on successful execution.
    ///
    /// @param depositAssets Amount of underlying assets to deposit.
    /// @param nonce Executor-chosen nonce.
    function test_emitsPolicyExecuted(uint256 depositAssets, uint256 nonce) public {
        depositAssets = bound(depositAssets, 1, MAX_DEPOSIT);
        loanToken.mint(address(account), depositAssets);

        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({depositAssets: depositAssets});
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyDataWithSig(binding, ld, nonce, 0);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyExecuted(policyId, address(account), address(policy), keccak256(executionData));
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }
}
