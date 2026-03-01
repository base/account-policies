// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Vm} from "forge-std/Vm.sol";

import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title CancelNoncesTest
///
/// @notice Tests for `AOAPolicy.cancelNonces`.
contract CancelNoncesTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the supplied config preimage does not match the stored hash.
    ///
    /// @param wrongConfigSuffix Arbitrary bytes that produce a different config hash.
    function test_reverts_whenConfigHashMismatch(bytes calldata wrongConfigSuffix) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory wrongConfig = abi.encode(AOAPolicy.AOAConfig({executor: executor}), wrongConfigSuffix);
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = 0;

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, wrongConfig);
    }

    /// @notice Reverts when the caller is not the executor.
    ///
    /// @param caller Arbitrary non-executor address.
    /// @param nonce Nonce to attempt to cancel.
    function test_reverts_whenCallerIsNotExecutor(address caller, uint256 nonce) public {
        vm.assume(caller != executor);

        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.UnauthorizedCanceller.selector, caller, executor));
        vm.prank(caller);
        policy.cancelNonces(policyId, nonces, policyConfig);
    }

    /// @notice Reverts when the account (not the executor) attempts to cancel nonces.
    function test_reverts_whenCallerIsAccount() public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = 0;

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.UnauthorizedCanceller.selector, address(account), executor));
        vm.prank(address(account));
        policy.cancelNonces(policyId, nonces, policyConfig);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Cancels a single nonce and emits `NonceCancelled`.
    ///
    /// @param nonce The nonce to cancel.
    function test_cancelsSingleNonce(uint256 nonce) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;

        vm.expectEmit(true, false, false, true, address(policy));
        emit AOAPolicy.NonceCancelled(policyId, nonce, executor);

        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);
    }

    /// @notice Cancels multiple nonces in a single batch call, emitting one event per nonce.
    ///
    /// @param nonceA First nonce to cancel.
    /// @param nonceB Second nonce to cancel.
    /// @param nonceC Third nonce to cancel.
    function test_cancelsBatch(uint256 nonceA, uint256 nonceB, uint256 nonceC) public {
        vm.assume(nonceA != nonceB && nonceB != nonceC && nonceA != nonceC);

        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](3);
        nonces[0] = nonceA;
        nonces[1] = nonceB;
        nonces[2] = nonceC;

        vm.expectEmit(true, false, false, true, address(policy));
        emit AOAPolicy.NonceCancelled(policyId, nonceA, executor);
        vm.expectEmit(true, false, false, true, address(policy));
        emit AOAPolicy.NonceCancelled(policyId, nonceB, executor);
        vm.expectEmit(true, false, false, true, address(policy));
        emit AOAPolicy.NonceCancelled(policyId, nonceC, executor);

        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);
    }

    /// @notice Cancelled nonce prevents subsequent execution with that nonce.
    ///
    /// @param nonce The nonce to cancel then attempt to execute with.
    function test_cancelledNoncePreventsExecution(uint256 nonce) public {
        bytes32 policyId = policyManager.getPolicyId(binding);

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);

        bytes memory executionData = _buildExecutionData(bytes(""), nonce, 0);

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.ExecutionNonceAlreadyUsed.selector, policyId, nonce));
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Silently skips nonces already consumed by a prior execution (no revert, no event).
    ///
    /// @param nonce The nonce to first execute with, then attempt to cancel.
    function test_skipsAlreadyUsedNonce(uint256 nonce) public {
        bytes32 policyId = policyManager.getPolicyId(binding);

        bytes memory executionData = _buildExecutionData(bytes(""), nonce, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;

        vm.recordLogs();
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != AOAPolicy.NonceCancelled.selector);
        }
    }

    /// @notice Cancelling the same nonce twice is idempotent — second call emits no event.
    ///
    /// @param nonce The nonce to cancel twice.
    function test_idempotent_noDuplicateEvent(uint256 nonce) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;

        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);

        vm.recordLogs();
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != AOAPolicy.NonceCancelled.selector);
        }
    }

    /// @notice Nonce cancellation works even when the policy is paused.
    ///
    /// @param nonce The nonce to cancel while paused.
    function test_worksWhenPaused(uint256 nonce) public {
        vm.prank(owner);
        policy.pause();

        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](1);
        nonces[0] = nonce;

        vm.expectEmit(true, false, false, true, address(policy));
        emit AOAPolicy.NonceCancelled(policyId, nonce, executor);

        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);
    }

    /// @notice Empty nonce array is a no-op (no revert, no events).
    function test_emptyArrayIsNoop() public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        uint256[] memory nonces = new uint256[](0);

        vm.recordLogs();
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != AOAPolicy.NonceCancelled.selector);
        }
    }

    /// @notice In a batch with mixed fresh and already-used nonces, only fresh nonces emit events.
    ///
    /// @param freshNonce A nonce that has not been used.
    /// @param usedNonce A nonce consumed by a prior execution.
    function test_batchMixedFreshAndUsed(uint256 freshNonce, uint256 usedNonce) public {
        vm.assume(freshNonce != usedNonce);

        bytes32 policyId = policyManager.getPolicyId(binding);

        bytes memory executionData = _buildExecutionData(bytes(""), usedNonce, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        uint256[] memory nonces = new uint256[](2);
        nonces[0] = usedNonce;
        nonces[1] = freshNonce;

        vm.expectEmit(true, false, false, true, address(policy));
        emit AOAPolicy.NonceCancelled(policyId, freshNonce, executor);

        vm.recordLogs();
        vm.prank(executor);
        policy.cancelNonces(policyId, nonces, policyConfig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 cancelCount;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == AOAPolicy.NonceCancelled.selector) {
                cancelCount++;
            }
        }
        assertEq(cancelCount, 1);
    }
}
