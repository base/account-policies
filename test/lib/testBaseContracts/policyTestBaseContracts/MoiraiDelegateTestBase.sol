// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

import {MockCoinbaseSmartWallet} from "../../mocks/MockCoinbaseSmartWallet.sol";

/// @title MoiraiDelegateTestBase
///
/// @notice Shared fixture for testing MoiraiDelegate policy semantics.
abstract contract MoiraiDelegateTestBase is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    bytes32 internal constant SINGLE_EXECUTOR_UNINSTALL_TYPEHASH = keccak256(
        "SingleExecutorUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)"
    );

    bytes32 internal constant EXECUTION_TYPEHASH = keccak256(
        "Execution(bytes32 policyId,address account,bytes32 policyConfigHash,ExecutionData executionData)"
        "ExecutionData(bytes actionData,uint256 nonce,uint256 deadline)"
    );
    bytes32 internal constant EXECUTION_DATA_TYPEHASH =
        keccak256("ExecutionData(bytes actionData,uint256 nonce,uint256 deadline)");

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal executorPk = uint256(keccak256("executor"));
    address internal executor = vm.addr(executorPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    MoiraiDelegate internal policy;

    function setUpMoiraiBase() internal {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        vm.etch(0x0000bc370E4DC924F427d84e2f4B9Ec81626ba7E, hex"01");
        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new MoiraiDelegate(address(policyManager), owner);

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));
    }

    /// @notice Builds an encoded `MoiraiConfig` with optional time-lock and executor.
    ///
    /// @param unlockTimestamp The unlock timestamp. Zero means no time-lock.
    /// @param executor_ The executor address. Zero means no consensus required.
    ///
    /// @return Encoded `MoiraiConfig` bytes.
    function _buildMoiraiConfig(uint256 unlockTimestamp, address executor_) internal pure returns (bytes memory) {
        return _buildMoiraiConfig(unlockTimestamp, executor_, address(0), 0, "");
    }

    /// @notice Builds an encoded policy config with full call parameters.
    ///
    /// @param unlockTimestamp The unlock timestamp. Zero means no time-lock.
    /// @param executor_ The executor address. Zero means no consensus required.
    /// @param target_ Target address for the delegated call.
    /// @param value_ ETH value to send with the call.
    /// @param callData_ Calldata to pass to `target_`.
    ///
    /// @return Canonical `abi.encode(SingleExecutorConfig, abi.encode(MoiraiConfig))` bytes.
    function _buildMoiraiConfig(
        uint256 unlockTimestamp,
        address executor_,
        address target_,
        uint256 value_,
        bytes memory callData_
    ) internal pure returns (bytes memory) {
        return abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor_}),
            abi.encode(
                MoiraiDelegate.MoiraiConfig({
                    target: target_, value: value_, callData: callData_, unlockTimestamp: unlockTimestamp
                })
            )
        );
    }

    /// @notice Builds a `PolicyBinding` for the default account and policy.
    ///
    /// @param policyConfig Encoded policy config bytes.
    /// @param salt Binding salt for uniqueness.
    ///
    /// @return binding The constructed `PolicyBinding`.
    function _buildBinding(bytes memory policyConfig, uint256 salt)
        internal
        view
        returns (PolicyManager.PolicyBinding memory binding)
    {
        return PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfig: policyConfig
        });
    }

    /// @notice Installs a policy and returns its policyId.
    ///
    /// @param config Encoded policy config bytes.
    /// @param salt Binding salt for uniqueness.
    ///
    /// @return policyId The installed policy identifier.
    function _buildAndInstall(bytes memory config, uint256 salt) internal returns (bytes32 policyId) {
        PolicyManager.PolicyBinding memory binding = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(binding);
        return policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }

    /// @notice Signs a policy install intent with the owner key.
    ///
    /// @param binding_ The binding to sign.
    ///
    /// @return Encoded ERC-6492-compatible signature bytes.
    function _signInstall(PolicyManager.PolicyBinding memory binding_) internal view returns (bytes memory) {
        bytes32 policyId = policyManager.getPolicyId(binding_);
        bytes32 structHash = keccak256(abi.encode(policyManager.INSTALL_POLICY_TYPEHASH(), policyId, uint256(0)));
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    /// @notice Builds executor-signed execution data for a MoiraiDelegate policy.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param policyConfig Full config preimage bytes.
    /// @param actionData Policy-specific action payload.
    /// @param nonce Execution nonce used for replay protection.
    /// @param deadline Optional signature expiry timestamp (seconds). Zero means no expiry.
    ///
    /// @return ABI-encoded `(SingleExecutorExecutionData, bytes actionData)`.
    function _buildExecutionData(
        bytes32 policyId,
        bytes memory policyConfig,
        bytes memory actionData,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 configHash = keccak256(policyConfig);
        bytes32 executionDataHash =
            keccak256(abi.encode(EXECUTION_DATA_TYPEHASH, keccak256(actionData), nonce, deadline));
        bytes32 structHash =
            keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, address(account), configHash, executionDataHash));
        bytes32 digest = _hashTypedData(address(policy), "Moirai Delegate", "1", structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        return abi.encode(
            SingleExecutorPolicy.SingleExecutorExecutionData({nonce: nonce, deadline: deadline, signature: sig}),
            actionData
        );
    }

    /// @notice Signs a replace intent with the owner key.
    ///
    /// @param oldPolicyId Old policy identifier being replaced.
    /// @param oldPolicyConfig Old policy config preimage.
    /// @param newPolicyId New policy identifier.
    ///
    /// @return ERC-6492-compatible signature bytes.
    function _signReplace(bytes32 oldPolicyId, bytes memory oldPolicyConfig, bytes32 newPolicyId)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                policyManager.REPLACE_POLICY_TYPEHASH(),
                address(account),
                address(policy),
                oldPolicyId,
                keccak256(oldPolicyConfig),
                newPolicyId,
                uint256(0)
            )
        );
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    /// @notice Signs an executor uninstall intent with the executor private key.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param configHash Config hash committed at install time.
    /// @param deadline Optional signature expiry timestamp (seconds). Zero means no expiry.
    ///
    /// @return uninstallData ABI-encoded `(bytes signature, uint256 deadline)`.
    function _signExecutorUninstall(bytes32 policyId, bytes32 configHash, uint256 deadline)
        internal
        view
        returns (bytes memory uninstallData)
    {
        bytes32 structHash = keccak256(
            abi.encode(SINGLE_EXECUTOR_UNINSTALL_TYPEHASH, policyId, address(account), configHash, deadline)
        );
        bytes32 digest = _hashTypedData(address(policy), "Moirai Delegate", "1", structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        return abi.encode(abi.encodePacked(r, s, v), deadline);
    }

    /// @notice Computes an EIP-712 typed-data digest.
    ///
    /// @param verifyingContract The contract whose domain separator to use.
    /// @param name EIP-712 domain name.
    /// @param version EIP-712 domain version.
    /// @param structHash Hash of the typed struct.
    ///
    /// @return EIP-712 digest.
    function _hashTypedData(address verifyingContract, string memory name, string memory version, bytes32 structHash)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, verifyingContract
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}
