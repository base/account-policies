// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";

import {
    MoiraiDelegatePolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegatePolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Tests for `MoiraiDelegate` execution behavior (`_onAOAExecute`).
///
/// @dev AOA-inherited execute behavior (pause gate, executor sig, nonce replay, deadline) is covered
///      in `test/unit/policies/AOAPolicy/execute.t.sol`. This suite covers MoiraiDelegate-specific
///      execution logic only.
contract ExecuteTest is MoiraiDelegatePolicyTestBase {
    function setUp() public {
        setUpInfrastructure();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when executing a delay-only policy before the unlock timestamp.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenTimelockNotMet(uint256 nonce) public {
        uint256 unlockTimestamp = block.timestamp + 1000;
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, address(0)));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes memory actionData = _buildActionDataNoConsensus();
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(MoiraiDelegate.TimelockNotMet.selector, block.timestamp, unlockTimestamp)
        );
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when executing a consensus-only policy with an invalid consensus signature.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenConsensusSignatureInvalid(uint256 nonce) public {
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(0, consensusSigner));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        // Sign with wrong key (owner instead of consensusSigner).
        bytes32 structHash =
            keccak256(abi.encode(CONSENSUS_APPROVAL_TYPEHASH, policyId, address(account), keccak256(config)));
        bytes32 digest = _hashTypedData(address(policy), POLICY_DOMAIN_NAME, POLICY_DOMAIN_VERSION, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        bytes memory actionData = abi.encode(MoiraiDelegate.DelegateExecution({consensusSignature: badSig}));
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.expectRevert(MoiraiDelegate.InvalidConsensusSignature.selector);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when executing a policy with both conditions and only the timelock is unmet.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_withBothConditions_whenTimelockNotMet(uint256 nonce) public {
        uint256 unlockTimestamp = block.timestamp + 1000;
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, consensusSigner));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes memory actionData = _buildActionDataWithConsensus(policyId, keccak256(config));
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.expectRevert(
            abi.encodeWithSelector(MoiraiDelegate.TimelockNotMet.selector, block.timestamp, unlockTimestamp)
        );
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when executing a policy with both conditions and only the consensus sig is invalid.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_withBothConditions_whenConsensusInvalid(uint256 nonce) public {
        uint256 unlockTimestamp = block.timestamp;
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, consensusSigner));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes memory actionData = _buildActionDataNoConsensus();
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.expectRevert(MoiraiDelegate.InvalidConsensusSignature.selector);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    /// @notice Reverts when attempting to execute with a nonce that has already been used (replay protection).
    ///
    /// @param nonce Executor-chosen nonce.
    function test_reverts_whenNonceAlreadyUsed(uint256 nonce) public {
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp, address(0)));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes memory actionData = _buildActionDataNoConsensus();
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);

        // Replay the same nonce.
        vm.expectRevert(abi.encodeWithSelector(AOAPolicy.ExecutionNonceAlreadyUsed.selector, policyId, nonce));
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Executes successfully when only a timelock is configured and the timestamp has passed.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_executesWithDelay(uint256 nonce) public {
        uint256 unlockTimestamp = block.timestamp + 100;
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, address(0)));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        vm.warp(unlockTimestamp);

        uint256 callsBefore = callReceiver.calls();
        bytes memory actionData = _buildActionDataNoConsensus();
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertEq(callReceiver.calls(), callsBefore + 1);
    }

    /// @notice Executes successfully when only a consensus signer is configured and the signature is valid.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_executesWithConsensusSigner(uint256 nonce) public {
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(0, consensusSigner));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        uint256 callsBefore = callReceiver.calls();
        bytes memory actionData = _buildActionDataWithConsensus(policyId, keccak256(config));
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertEq(callReceiver.calls(), callsBefore + 1);
    }

    /// @notice Executes successfully when both conditions are configured and both are met.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_executesWithBothConditions(uint256 nonce) public {
        uint256 unlockTimestamp = block.timestamp + 100;
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, consensusSigner));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        vm.warp(unlockTimestamp);

        uint256 callsBefore = callReceiver.calls();
        bytes memory actionData = _buildActionDataWithConsensus(policyId, keccak256(config));
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertEq(callReceiver.calls(), callsBefore + 1);
    }

    /// @notice Forwards the pinned callData to the target on execution.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_forwardsPinnedCallDataToTarget(uint256 nonce) public {
        bytes32 tag = bytes32("moirai");
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp, address(0)));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes memory actionData = _buildActionDataNoConsensus();
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);

        assertEq(callReceiver.lastTag(), tag);
        assertEq(callReceiver.lastCaller(), address(account));
    }

    /// @notice Emits PolicyExecuted on successful execution.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_emitsPolicyExecuted(uint256 nonce) public {
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp, address(0)));
        (bytes32 policyId, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes memory actionData = _buildActionDataNoConsensus();
        bytes memory executionData = _buildExecutionData(b, actionData, nonce, 0);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyExecuted(policyId, address(account), address(policy), keccak256(executionData));

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, config, executionData);
    }
}
