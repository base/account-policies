// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../src/policies/AOAPolicy.sol";
import {MoiraiDelegate} from "../../../src/policies/MoiraiDelegate.sol";

import {
    MoiraiDelegatePolicyTestBase
} from "../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegatePolicyTestBase.sol";
import {CallReceiver} from "../../lib/mocks/CallReceiver.sol";

// =============================================================
//                         Install
// =============================================================

/// @title InstallTest
///
/// @notice Tests for `MoiraiDelegate` install-time behavior (`_onAOAInstall`).
contract InstallTest is MoiraiDelegatePolicyTestBase {
    function setUp() public {
        setUpInfrastructure();
    }

    // ---------------------------------------------------------
    // Reverts
    // ---------------------------------------------------------

    /// @notice Reverts when neither timelock nor consensus signer is configured.
    function test_reverts_whenNoConditionSpecified() public {
        MoiraiDelegate.DelegateConfig memory cfg = MoiraiDelegate.DelegateConfig({
            target: address(callReceiver),
            value: 0,
            callData: abi.encodeCall(CallReceiver.ping, (bytes32("test"))),
            unlockTimestamp: 0,
            consensusSigner: address(0)
        });
        bytes memory config = _buildPolicyConfig(cfg);

        PolicyManager.PolicyBinding memory b = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 0,
            policyConfig: config
        });
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MoiraiDelegate.NoConditionSpecified.selector);
        policyManager.installWithSignature(b, userSig, bytes(""));
    }

    /// @notice Reverts when the target address is zero.
    function test_reverts_whenTargetIsZero() public {
        MoiraiDelegate.DelegateConfig memory cfg = MoiraiDelegate.DelegateConfig({
            target: address(0),
            value: 0,
            callData: bytes(""),
            unlockTimestamp: block.timestamp + 1,
            consensusSigner: address(0)
        });
        bytes memory config = _buildPolicyConfig(cfg);

        PolicyManager.PolicyBinding memory b = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 0,
            policyConfig: config
        });
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MoiraiDelegate.ZeroTarget.selector);
        policyManager.installWithSignature(b, userSig, bytes(""));
    }

    // ---------------------------------------------------------
    // Success
    // ---------------------------------------------------------

    /// @notice Installs successfully with only a timelock configured.
    ///
    /// @param unlockTimestamp Fuzzed unlock timestamp (bounded to the future).
    function test_installsWithDelay(uint256 unlockTimestamp) public {
        unlockTimestamp = bound(unlockTimestamp, block.timestamp + 1, type(uint256).max);

        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, address(0)));
        (, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes32 policyId = policyManager.getPolicyId(b);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Installs successfully with only a consensus signer configured.
    function test_installsWithConsensusSigner() public {
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(0, consensusSigner));
        (, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes32 policyId = policyManager.getPolicyId(b);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Installs successfully with both a timelock and a consensus signer configured.
    ///
    /// @param unlockTimestamp Fuzzed unlock timestamp (bounded to the future).
    function test_installsWithBothConditions(uint256 unlockTimestamp) public {
        unlockTimestamp = bound(unlockTimestamp, block.timestamp + 1, type(uint256).max);

        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, consensusSigner));
        (, PolicyManager.PolicyBinding memory b) = _install(config, 0);

        bytes32 policyId = policyManager.getPolicyId(b);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Two policies with identical configuration can be installed using different salts.
    ///
    /// @param salt1 Salt for the first binding.
    /// @param salt2 Salt for the second binding (must differ from salt1).
    function test_installsIdenticalConfigWithDifferentSalts(uint256 salt1, uint256 salt2) public {
        vm.assume(salt1 != salt2);

        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp + 1, address(0)));
        (bytes32 policyId1, PolicyManager.PolicyBinding memory b1) = _install(config, salt1);
        (bytes32 policyId2, PolicyManager.PolicyBinding memory b2) = _install(config, salt2);

        assertNotEq(policyId1, policyId2);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId1));
        assertTrue(policyManager.isPolicyActive(address(policy), policyId2));
        assertEq(b1.policyConfig, b2.policyConfig);
    }

    /// @notice A third policy with a different configuration can be installed alongside existing ones.
    ///
    /// @param unlockTimestamp Fuzzed unlock timestamp for the third policy.
    function test_installsThirdPolicyWithDifferentConfig(uint256 unlockTimestamp) public {
        unlockTimestamp = bound(unlockTimestamp, block.timestamp + 1, type(uint256).max);

        bytes memory config1 = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp + 1, address(0)));
        bytes memory config2 = _buildPolicyConfig(_defaultDelegateConfig(0, consensusSigner));
        bytes memory config3 = _buildPolicyConfig(_defaultDelegateConfig(unlockTimestamp, consensusSigner));

        (bytes32 policyId1,) = _install(config1, 0);
        (bytes32 policyId2,) = _install(config2, 1);
        (bytes32 policyId3,) = _install(config3, 2);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId1));
        assertTrue(policyManager.isPolicyActive(address(policy), policyId2));
        assertTrue(policyManager.isPolicyActive(address(policy), policyId3));
        assertNotEq(policyId1, policyId3);
        assertNotEq(policyId2, policyId3);
    }

    /// @notice Emits PolicyInstalled on successful install.
    function test_emitsPolicyInstalled() public {
        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp + 1, address(0)));
        PolicyManager.PolicyBinding memory b = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 0,
            policyConfig: config
        });
        bytes32 expectedPolicyId = policyManager.getPolicyId(b);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyInstalled(expectedPolicyId, address(account), address(policy));

        bytes memory userSig = _signInstall(b);
        policyManager.installWithSignature(b, userSig, bytes(""));
    }
}

// =============================================================
//                         Execute
// =============================================================

/// @title ExecuteTest
///
/// @notice Tests for `MoiraiDelegate` execution behavior (`_onAOAExecute`).
contract ExecuteTest is MoiraiDelegatePolicyTestBase {
    function setUp() public {
        setUpInfrastructure();
    }

    // ---------------------------------------------------------
    // Reverts
    // ---------------------------------------------------------

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

    // ---------------------------------------------------------
    // Success
    // ---------------------------------------------------------

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

// =============================================================
//                         Uninstall
// =============================================================

/// @title UninstallTest
///
/// @notice Tests for `MoiraiDelegate` uninstall behavior.
contract UninstallTest is MoiraiDelegatePolicyTestBase {
    bytes32 internal policyId;
    PolicyManager.PolicyBinding internal binding;
    bytes internal policyConfig;

    function setUp() public {
        setUpInfrastructure();

        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp + 1, address(0)));
        (policyId, binding) = _install(config, 0);
        policyConfig = config;
    }

    /// @notice Successfully uninstalls an active policy when called by the account.
    function test_uninstalls() public {
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), policyConfig: bytes(""), validAfter: 0, validUntil: 0, salt: 0
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertFalse(policyManager.isPolicyActive(address(policy), policyId));
        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    /// @notice Uninstalling an already-uninstalled policy is idempotent and does not revert.
    function test_uninstall_isIdempotent() public {
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), policyConfig: bytes(""), validAfter: 0, validUntil: 0, salt: 0
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));

        // Second uninstall: should succeed without reverting.
        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    /// @notice Emits PolicyUninstalled on successful uninstall.
    function test_emitsPolicyUninstalled() public {
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), policyConfig: bytes(""), validAfter: 0, validUntil: 0, salt: 0
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyUninstalled(policyId, address(account), address(policy));

        vm.prank(address(account));
        policyManager.uninstall(payload);
    }
}
