// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {TransferSettingsPolicy} from "../../../../src/policies/TransferSettingsPolicy.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

import {FalseReturningERC20} from "../../../lib/mocks/FalseReturningERC20.sol";
import {MintableERC20} from "../../../lib/mocks/MintableERC20.sol";
import {
    TransferSettingsPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/TransferSettingsPolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `TransferSettingsPolicy._onExecute` behavior.
contract ExecuteTest is TransferSettingsPolicyTestBase {
    function setUp() public {
        setUpTransferSettingsBase();
        vm.deal(address(account), 100 ether);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Executes successfully when only a time-lock is configured and the lock has expired.
    function test_success_withDelayOnly() public {
        uint256 unlockTime = block.timestamp + 1 days;
        bytes memory config = _buildTransferConfig(unlockTime, address(0));
        bytes32 policyId = _buildAndInstall(config, 0);

        vm.warp(unlockTime);

        assertFalse(policy.executed(policyId));
        policyManager.execute(address(policy), policyId, config, bytes("0x01"));
        assertTrue(policy.executed(policyId));
    }

    /// @notice Executes successfully when only an executor signature is required and a valid sig is provided.
    function test_success_withExecutorOnly() public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);

        assertFalse(policy.executed(policyId));
        policyManager.execute(address(policy), policyId, config, executionData);
        assertTrue(policy.executed(policyId));
    }

    /// @notice Executes a native ETH transfer from the account to a recipient.
    function test_success_executesNativeTransfer() public {
        address recipient = makeAddr("recipient");
        uint256 amount = 1 ether;
        vm.deal(address(account), amount);

        bytes memory config = _buildTransferConfig(0, executor, recipient, amount, address(0));
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertEq(recipient.balance, amount);
    }

    /// @notice Executes an ERC20 transfer from the account to a recipient.
    function test_success_executesERC20Transfer() public {
        MintableERC20 token = new MintableERC20("Test Token", "TT");
        address recipient = makeAddr("recipient");
        uint256 amount = 500e18;
        token.mint(address(account), amount);

        bytes memory config = _buildTransferConfig(0, executor, recipient, amount, address(token));
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertEq(token.balanceOf(recipient), amount);
        assertEq(token.balanceOf(address(account)), 0);
    }

    /// @notice Executes successfully when both time-lock and executor signature are required and both are satisfied.
    function test_success_withBothConditions() public {
        uint256 unlockTime = block.timestamp + 1 days;
        bytes memory config = _buildTransferConfig(unlockTime, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        vm.warp(unlockTime);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);

        assertFalse(policy.executed(policyId));
        policyManager.execute(address(policy), policyId, config, executionData);
        assertTrue(policy.executed(policyId));
    }

    // =============================================================
    // isExecuted state transitions
    // =============================================================

    /// @notice isExecuted returns false before execution and true after.
    function test_isExecuted_falseBeforeTrueAfter() public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        assertFalse(policy.executed(policyId));

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertTrue(policy.executed(policyId));
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policy is paused by the admin.
    ///
    /// @param executionData Arbitrary execution data (paused check fires before any decoding).
    function test_reverts_whenPaused(bytes calldata executionData) public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        vm.prank(owner);
        policy.pause();

        vm.expectRevert(Pausable.EnforcedPause.selector);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when the unlock timestamp has not yet been reached.
    function test_reverts_beforeUnlockTime() public {
        uint256 unlockTime = block.timestamp + 1 days;
        bytes memory config = _buildTransferConfig(unlockTime, address(0));
        bytes32 policyId = _buildAndInstall(config, 0);

        vm.expectRevert(
            abi.encodeWithSelector(TransferSettingsPolicy.BeforeUnlockTimestamp.selector, block.timestamp, unlockTime)
        );
        policyManager.execute(address(policy), policyId, config, bytes("0x01"));
    }

    /// @notice Reverts when the executor signature is invalid.
    ///
    /// @param badSig Arbitrary bytes that do not form a valid executor signature.
    function test_reverts_withInvalidSignature(bytes calldata badSig) public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = abi.encode(
            SingleExecutorPolicy.SingleExecutorExecutionData({nonce: 0, deadline: 0, signature: badSig}), bytes("")
        );

        vm.expectRevert(abi.encodeWithSelector(SingleExecutorPolicy.Unauthorized.selector, address(this)));
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when executing with a nonce that was pre-cancelled by the executor.
    ///
    /// @param nonce Execution nonce that will be pre-cancelled.
    function test_reverts_withReplayedNonce(uint256 nonce) public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, config);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(SingleExecutorPolicy.ExecutionNonceAlreadyUsed.selector, policyId, nonce)
        );
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when the executor signature deadline has expired.
    ///
    /// @param deadline Non-zero deadline that will be exceeded.
    /// @param nonce Execution nonce.
    function test_reverts_withExpiredDeadline(uint256 deadline, uint256 nonce) public {
        deadline = bound(deadline, 1, type(uint256).max - 1);
        vm.warp(deadline + 1);

        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SingleExecutorPolicy.SignatureExpired.selector, block.timestamp, deadline)
        );
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when both conditions are required but only the time-lock is met (no valid signature provided).
    function test_reverts_withBothConditions_onlyTimeMet() public {
        uint256 unlockTime = block.timestamp + 1 days;
        bytes memory config = _buildTransferConfig(unlockTime, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        vm.warp(unlockTime);

        bytes memory executionData = abi.encode(
            SingleExecutorPolicy.SingleExecutorExecutionData({nonce: 0, deadline: 0, signature: bytes("")}), bytes("")
        );
        vm.expectRevert(abi.encodeWithSelector(SingleExecutorPolicy.Unauthorized.selector, address(this)));
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when both conditions are required but only the executor signature is provided (time not met).
    function test_reverts_withBothConditions_onlyConsensusMet() public {
        uint256 unlockTime = block.timestamp + 1 days;
        bytes memory config = _buildTransferConfig(unlockTime, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);

        vm.expectRevert(
            abi.encodeWithSelector(TransferSettingsPolicy.BeforeUnlockTimestamp.selector, block.timestamp, unlockTime)
        );
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts on a second execute attempt after the first succeeds.
    function test_reverts_alreadyExecuted() public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, config, executionData);

        bytes memory executionData2 = _buildExecutionData(policyId, config, bytes(""), 1, 0);
        vm.expectRevert(abi.encodeWithSelector(TransferSettingsPolicy.AlreadyExecuted.selector, policyId));
        policyManager.execute(address(policy), policyId, config, executionData2);
    }

    /// @notice Cancelling a nonce already consumed by execution is a no-op (no event, no revert).
    function test_noOp_cancelNonce_afterExecution() public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        uint256 nonce = 42;
        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), nonce, 0);
        policyManager.execute(address(policy), policyId, config, executionData);

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;
        vm.recordLogs();
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, config);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @notice Reverts when the ERC20 token returns `false` from `transfer` without reverting.
    ///
    /// @dev `CoinbaseSmartWallet.execute` propagates inner-call reverts but does not inspect the ERC20
    ///      return value. `_onPostExecute` catches the silent failure via a balance check.
    function test_reverts_whenERC20TransferReturnsFalse() public {
        FalseReturningERC20 token = new FalseReturningERC20();
        address recipient = makeAddr("recipient");
        uint256 amount = 500e18;
        token.mint(address(account), amount);

        bytes memory config = _buildTransferConfig(0, executor, recipient, amount, address(token));
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes(""), 0, 0);

        vm.expectRevert(TransferSettingsPolicy.ERC20TransferFailed.selector);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when non-empty action data is provided to an executor-required policy.
    function test_reverts_withNonEmptyActionData() public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        bytes memory executionData = _buildExecutionData(policyId, config, bytes("0x01"), 0, 0);

        vm.expectRevert(TransferSettingsPolicy.UnexpectedActionData.selector);
        policyManager.execute(address(policy), policyId, config, executionData);
    }
}
