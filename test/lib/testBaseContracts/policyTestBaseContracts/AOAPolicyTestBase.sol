// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";

import {MockCoinbaseSmartWallet} from "../../mocks/MockCoinbaseSmartWallet.sol";

/// @notice Minimal AOA policy used for testing shared AOA behaviors.
contract AOATestPolicy is AOAPolicy {
    bytes32 public lastExecutePolicyId;
    address public lastExecuteAccount;
    address public lastExecuteExecutor;
    bytes public lastActionData;
    uint256 public executeCalls;

    bytes32 public lastUninstallPolicyId;
    address public lastUninstallAccount;
    address public lastUninstallCaller;
    uint256 public uninstallCalls;

    constructor(address policyManager, address admin) AOAPolicy(policyManager, admin) {}

    function _onAOAExecute(
        bytes32 policyId,
        address account,
        AOAConfig memory aoaConfig,
        bytes memory,
        bytes memory actionData
    ) internal override returns (bytes memory, bytes memory) {
        lastExecutePolicyId = policyId;
        lastExecuteAccount = account;
        lastExecuteExecutor = aoaConfig.executor;
        lastActionData = actionData;
        executeCalls++;
        return ("", "");
    }

    function _onAOAUninstall(bytes32 policyId, address account, address caller) internal override {
        lastUninstallPolicyId = policyId;
        lastUninstallAccount = account;
        lastUninstallCaller = caller;
        uninstallCalls++;
    }

    /// @dev Exposes internal config hash for testing.
    function getConfigHash(bytes32 policyId) external view returns (bytes32) {
        return _configHashByPolicyId[policyId];
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "AOA Test Policy";
        version = "1";
    }
}

/// @title AOAPolicyTestBase
///
/// @notice Shared fixture for testing AOA wrapper semantics.
abstract contract AOAPolicyTestBase is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    bytes32 internal constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 executionDataHash)");
    bytes32 internal constant EXECUTION_DATA_TYPEHASH =
        keccak256("ExecutionData(bytes actionData,uint256 nonce,uint256 deadline)");
    bytes32 internal constant AOA_UNINSTALL_TYPEHASH =
        keccak256("AOAUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)");

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal executorPk = uint256(keccak256("executor"));
    address internal executor = vm.addr(executorPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    AOATestPolicy internal policy;

    bytes internal policyConfig;
    PolicyManager.PolicyBinding internal binding;

    function setUpAOABase() internal {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new AOATestPolicy(address(policyManager), owner);

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        policyConfig = abi.encode(AOAPolicy.AOAConfig({executor: executor}), bytes(""));
        binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 0,
            policyConfig: policyConfig
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }

    /// @dev Builds a binding for the default account + policy using given config and salt.
    function _binding(bytes memory config, uint256 salt) internal view returns (PolicyManager.PolicyBinding memory) {
        return PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfig: config
        });
    }

    /// @dev Builds AOA execution data with a valid executor signature for the default binding.
    function _buildExecutionData(bytes memory actionData, uint256 nonce, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes32 configHash = keccak256(policyConfig);
        bytes32 executionDataHash =
            keccak256(abi.encode(EXECUTION_DATA_TYPEHASH, keccak256(actionData), nonce, deadline));
        bytes32 structHash =
            keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, address(account), configHash, executionDataHash));
        bytes32 digest = _hashTypedData(address(policy), "AOA Test Policy", "1", structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        return abi.encode(AOAPolicy.AOAExecutionData({nonce: nonce, deadline: deadline, signature: sig}), actionData);
    }

    /// @dev Signs an executor uninstall intent.
    function _signUninstall(bytes32 policyId, bytes32 configHash, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(AOA_UNINSTALL_TYPEHASH, policyId, address(account), configHash, deadline)
        );
        bytes32 digest = _hashTypedData(address(policy), "AOA Test Policy", "1", structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signReplace(
        address oldPolicy,
        bytes32 oldPolicyId,
        bytes memory oldPolicyConfig,
        bytes32 newPolicyId,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                policyManager.REPLACE_POLICY_TYPEHASH(),
                address(account),
                oldPolicy,
                oldPolicyId,
                keccak256(oldPolicyConfig),
                newPolicyId,
                deadline
            )
        );
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    function _signInstall(PolicyManager.PolicyBinding memory binding_) internal view returns (bytes memory) {
        return _signInstall(binding_, 0);
    }

    function _signInstall(PolicyManager.PolicyBinding memory binding_, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 policyId = policyManager.getPolicyId(binding_);
        bytes32 structHash = keccak256(abi.encode(policyManager.INSTALL_POLICY_TYPEHASH(), policyId, deadline));
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

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
