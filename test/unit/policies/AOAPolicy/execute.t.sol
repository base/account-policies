// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `AOAPolicy._onExecute` behavior (config hash check, executor sig, nonce, deadline).
contract ExecuteTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policy is paused, regardless of execution data content.
    ///
    /// @param executionData Arbitrary execution data (pause gate fires before any decoding).
    function test_reverts_whenPaused(bytes calldata executionData) public {
        vm.prank(owner);
        policy.pause();

        bytes32 policyId = policyManager.getPolicyId(binding);

        vm.expectRevert(Pausable.EnforcedPause.selector);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the supplied config hash does not match the stored config hash.
    ///
    /// @param configSuffix Arbitrary bytes appended to the wrong config (config hash check precedes execution data
    ///        decoding).
    /// @param executionData Arbitrary execution data (not reached).
    function test_reverts_whenConfigHashMismatch(bytes calldata configSuffix, bytes calldata executionData) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory wrongConfig =
            abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), configSuffix);
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        policyManager.execute(address(policy), policyId, wrongConfig, executionData);
    }

    /// @notice Reverts when the executor signature is invalid.
    ///
    /// @param nonce Executor-chosen nonce.
    /// @param badSig Arbitrary bytes that do not form a valid executor signature.
    function test_reverts_whenInvalidExecutorSignature(uint256 nonce, bytes calldata badSig) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData =
            abi.encode(AOAPolicy.AOAExecutionData({nonce: nonce, deadline: 0, signature: badSig}), bytes(""));

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.Unauthorized.selector, address(this)));
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the execution nonce has already been used.
    ///
    /// @param nonce Executor-chosen nonce.
    /// @param actionSeed Seed for generating action data.
    function test_reverts_whenNonceAlreadyUsed(uint256 nonce, bytes32 actionSeed) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory actionData = abi.encode(actionSeed);

        bytes memory executionData = _buildExecutionData(actionData, nonce, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        bytes memory executionData2 = _buildExecutionData(actionData, nonce, 0);
        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.ExecutionNonceAlreadyUsed.selector, policyId, nonce));
        policyManager.execute(address(policy), policyId, policyConfig, executionData2);
    }

    /// @notice Reverts when the executor signature deadline has passed.
    ///
    /// @param deadline Non-zero deadline that will be exceeded.
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenSignatureExpired(uint256 deadline, uint256 nonce) public {
        deadline = bound(deadline, 1, type(uint256).max - 1);
        vm.warp(deadline + 1);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _buildExecutionData(bytes(""), nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.SignatureExpired.selector, block.timestamp, deadline));
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Forwards the decoded AOA config and action data to `_onAOAExecute`.
    ///
    /// @param actionSeed Seed for generating action data.
    /// @param nonce Executor-chosen nonce.
    function test_callsOnAOAExecute(bytes32 actionSeed, uint256 nonce) public {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory actionData = abi.encode(actionSeed);
        bytes memory executionData = _buildExecutionData(actionData, nonce, 0);

        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        assertEq(policy.executeCalls(), 1);
        assertEq(policy.lastExecutePolicyId(), policyId);
        assertEq(policy.lastExecuteAccount(), address(account));
        assertEq(policy.lastExecuteExecutor(), executor);
        assertEq(policy.lastActionData(), actionData);
    }
}
