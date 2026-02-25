// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";

import {
    MoiraiDelegatePolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegatePolicyTestBase.sol";
import {CallReceiver} from "../../../lib/mocks/CallReceiver.sol";

/// @title InstallTest
///
/// @notice Tests for `MoiraiDelegate` install-time behavior (`_onAOAInstall`).
contract InstallTest is MoiraiDelegatePolicyTestBase {
    function setUp() public {
        setUpInfrastructure();
    }

    // =============================================================
    // Reverts
    // =============================================================

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

    // =============================================================
    // Success
    // =============================================================

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
