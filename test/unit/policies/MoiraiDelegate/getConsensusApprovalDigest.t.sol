// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";

import {
    MoiraiDelegatePolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegatePolicyTestBase.sol";

/// @title GetConsensusApprovalDigestTest
///
/// @notice Tests for `MoiraiDelegate.getConsensusApprovalDigest`, the external view that
///         exposes the EIP-712 digest a consensus signer must sign to approve a policy instance.
contract GetConsensusApprovalDigestTest is MoiraiDelegatePolicyTestBase {
    bytes32 internal policyId;
    PolicyManager.PolicyBinding internal binding;
    bytes internal policyConfig;

    function setUp() public {
        setUpInfrastructure();

        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(0, consensusSigner));
        (policyId, binding) = _install(config, 0);
        policyConfig = config;
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the supplied policyConfig preimage does not match the stored hash.
    ///
    /// @param wrongConfig Fuzzed bytes that (almost certainly) hash differently from the installed config.
    function test_reverts_whenConfigHashMismatch(bytes calldata wrongConfig) public {
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        policy.getConsensusApprovalDigest(policyId, address(account), wrongConfig);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Returns the expected EIP-712 digest for the installed policy instance.
    function test_returnsExpectedDigest() public view {
        bytes32 structHash =
            keccak256(abi.encode(CONSENSUS_APPROVAL_TYPEHASH, policyId, address(account), keccak256(policyConfig)));
        bytes32 expected = _hashTypedData(address(policy), POLICY_DOMAIN_NAME, POLICY_DOMAIN_VERSION, structHash);

        bytes32 actual = policy.getConsensusApprovalDigest(policyId, address(account), policyConfig);

        assertEq(actual, expected);
    }

    /// @notice The returned digest can be signed to produce a valid consensus signature for execution.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_digestEnablesValidConsensusSignature(uint256 nonce) public {
        bytes32 digest = policy.getConsensusApprovalDigest(policyId, address(account), policyConfig);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(consensusSignerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes memory actionData = abi.encode(MoiraiDelegate.DelegateExecution({consensusSignature: sig}));
        bytes memory executionData = _buildExecutionData(binding, actionData, nonce, 0);

        uint256 callsBefore = callReceiver.calls();

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        assertEq(callReceiver.calls(), callsBefore + 1);
    }

    /// @notice The digest is account-scoped: a digest for one account cannot authorize execution for another.
    ///
    /// @param nonce Executor-chosen nonce.
    function test_digestIsScopedToAccount(uint256 nonce) public {
        address otherAccount = makeAddr("otherAccount");

        // Compute digest for a different account — sign it with the correct consensus key.
        bytes32 digestForOther =
            policy.getConsensusApprovalDigest(policyId, otherAccount, policyConfig);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(consensusSignerPk, digestForOther);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Attempt to use that signature for the real account — should fail.
        bytes memory actionData = abi.encode(MoiraiDelegate.DelegateExecution({consensusSignature: sig}));
        bytes memory executionData = _buildExecutionData(binding, actionData, nonce, 0);

        vm.expectRevert(MoiraiDelegate.InvalidConsensusSignature.selector);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
    }
}
