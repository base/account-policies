// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";

import {CallReceiver} from "../../mocks/CallReceiver.sol";
import {MockCoinbaseSmartWallet} from "../../mocks/MockCoinbaseSmartWallet.sol";

/// @title MoiraiDelegatePolicyTestBase
///
/// @notice Shared fixture and helpers for `MoiraiDelegate` unit tests.
abstract contract MoiraiDelegatePolicyTestBase is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    bytes32 internal constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 executionDataHash)");
    bytes32 internal constant CONSENSUS_APPROVAL_TYPEHASH =
        keccak256("ConsensusApproval(bytes32 policyId,address account,bytes32 policyConfigHash)");

    bytes32 internal constant POLICY_DOMAIN_NAME = keccak256("Moirai Delegate");
    bytes32 internal constant POLICY_DOMAIN_VERSION = keccak256("1");

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal executorPk = uint256(keccak256("executor"));
    address internal executor = vm.addr(executorPk);
    uint256 internal consensusSignerPk = uint256(keccak256("consensusSigner"));
    address internal consensusSigner = vm.addr(consensusSignerPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    MoiraiDelegate internal policy;
    CallReceiver internal callReceiver;

    /// @dev Sets up contracts without installing any policy.
    function setUpInfrastructure() internal {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new MoiraiDelegate(address(policyManager), owner);
        callReceiver = new CallReceiver();

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));
    }

    /// @dev Builds the policyConfig bytes for a given DelegateConfig.
    function _buildPolicyConfig(MoiraiDelegate.DelegateConfig memory cfg) internal view returns (bytes memory) {
        return abi.encode(AOAPolicy.AOAConfig({executor: executor}), abi.encode(cfg));
    }

    /// @dev Builds a default DelegateConfig using the CallReceiver as target.
    function _defaultDelegateConfig(uint256 unlockTimestamp, address _consensusSigner)
        internal
        view
        returns (MoiraiDelegate.DelegateConfig memory)
    {
        return MoiraiDelegate.DelegateConfig({
            target: address(callReceiver),
            value: 0,
            callData: abi.encodeCall(CallReceiver.ping, (bytes32("moirai"))),
            unlockTimestamp: unlockTimestamp,
            consensusSigner: _consensusSigner
        });
    }

    /// @dev Installs a policy with the given policyConfig and salt.
    ///
    /// @return policyId Installed policy identifier.
    /// @return binding_ The binding used for installation.
    function _install(bytes memory config, uint256 salt)
        internal
        returns (bytes32 policyId, PolicyManager.PolicyBinding memory binding_)
    {
        binding_ = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfig: config
        });
        bytes memory userSig = _signInstall(binding_);
        policyId = policyManager.installWithSignature(binding_, userSig, bytes(""));
    }

    /// @dev Builds AOA execution data with a valid executor signature.
    ///
    /// @param binding_ Binding to sign for.
    /// @param actionData Policy-specific action payload.
    /// @param nonce Execution nonce.
    /// @param deadline Signature expiry (0 = no expiry).
    function _buildExecutionData(
        PolicyManager.PolicyBinding memory binding_,
        bytes memory actionData,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 digest = _getExecutionDigest(binding_, actionData, nonce, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        return abi.encode(AOAPolicy.AOAExecutionData({nonce: nonce, deadline: deadline, signature: sig}), actionData);
    }

    /// @dev Builds the DelegateExecution actionData with a consensus signature.
    ///
    /// @param policyId Policy identifier.
    /// @param configHash Hash of the policyConfig.
    function _buildActionDataWithConsensus(bytes32 policyId, bytes32 configHash) internal view returns (bytes memory) {
        bytes memory sig = _signConsensus(policyId, configHash);
        return abi.encode(MoiraiDelegate.DelegateExecution({consensusSignature: sig}));
    }

    /// @dev Builds the DelegateExecution actionData with an empty consensus signature.
    function _buildActionDataNoConsensus() internal pure returns (bytes memory) {
        return abi.encode(MoiraiDelegate.DelegateExecution({consensusSignature: bytes("")}));
    }

    /// @dev Signs a consensus approval for the given policy instance.
    function _signConsensus(bytes32 policyId, bytes32 configHash) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(CONSENSUS_APPROVAL_TYPEHASH, policyId, address(account), configHash));
        bytes32 digest = _hashTypedData(address(policy), POLICY_DOMAIN_NAME, POLICY_DOMAIN_VERSION, structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(consensusSignerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Signs an install intent for the given binding.
    function _signInstall(PolicyManager.PolicyBinding memory binding_) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getPolicyId(binding_);
        bytes32 digest = _hashTypedData(address(policyManager), keccak256("Policy Manager"), keccak256("1"), structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        return account.wrapSignature(0, abi.encodePacked(r, s, v));
    }

    /// @dev Computes the EIP-712 execution digest for the executor to sign.
    function _getExecutionDigest(
        PolicyManager.PolicyBinding memory binding_,
        bytes memory actionData,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 policyId = policyManager.getPolicyId(binding_);
        bytes32 executionDataHash = keccak256(abi.encode(keccak256(actionData), nonce, deadline));
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTION_TYPEHASH, policyId, address(account), keccak256(binding_.policyConfig), executionDataHash
            )
        );
        return _hashTypedData(address(policy), POLICY_DOMAIN_NAME, POLICY_DOMAIN_VERSION, structHash);
    }

    /// @dev Computes an EIP-712 typed data digest.
    function _hashTypedData(address verifyingContract, bytes32 nameHash, bytes32 versionHash, bytes32 structHash)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator =
            keccak256(abi.encode(DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, verifyingContract));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
