// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {PublicERC6492Validator} from "../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../src/PolicyManager.sol";
import {Policy} from "../../../src/policies/Policy.sol";

import {MockCoinbaseSmartWallet} from "../../lib/mocks/MockCoinbaseSmartWallet.sol";

/// @title NoopPolicy
///
/// @notice Minimal test policy that stores a config hash and records execution metadata.
contract NoopPolicy is Policy {
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    mapping(bytes32 policyId => bytes32 configHash) internal _configHash;
    uint256 public installCalls;
    bytes32 public lastExecutedPolicyId;
    address public lastCaller;

    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32 policyId, address, bytes calldata policyConfig, address) internal override {
        installCalls++;
        _configHash[policyId] = keccak256(policyConfig);
    }

    function _onUninstall(bytes32, address, bytes calldata, bytes calldata, address) internal override {}

    function _onExecute(bytes32 policyId, address, bytes calldata policyConfig, bytes calldata, address caller)
        internal
        override
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        bytes32 expected = _configHash[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);

        lastExecutedPolicyId = policyId;
        lastCaller = caller;

        return ("", "");
    }
}

/// @title ExecuteWithInstallTest
///
/// @notice Tests for `PolicyManager.executeWithInstall` and execution-bound install authorization.
contract ExecuteWithInstallTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    bytes32 internal constant POLICY_INSTALLED_EVENT_SIG = keccak256("PolicyInstalled(bytes32,address,address)");

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    NoopPolicy internal policy;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new NoopPolicy(address(policyManager));

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));
    }

    function test_executeWithInstall_canInstallAndExecuteAtomically_withExecutionBoundSignature() public {
        bytes memory policyConfig = abi.encode(uint256(123));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 42,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        bytes memory executionData = hex"beef";
        uint256 deadline = block.timestamp + 1 days;

        bytes memory userSig = _signInstallAndExecute(policyId, executionData, deadline);

        PolicyManager.InstallAndExecutePayload memory payload = PolicyManager.InstallAndExecutePayload({
            binding: binding,
            policyConfig: policyConfig,
            userSig: userSig,
            executionData: executionData,
            deadline: deadline
        });

        vm.expectRevert(PolicyManager.InvalidSignature.selector);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);

        policyManager.executeWithInstall(payload);

        assertTrue(policyManager.isPolicyInstalled(address(policy), policyId));
        assertEq(policy.lastExecutedPolicyId(), policyId);
        assertEq(policy.lastCaller(), address(this));
    }

    function test_executeWithInstall_isTypedWrapperForInstallAndExecute() public {
        bytes memory policyConfig = abi.encode(uint256(456));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 99,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        bytes memory executionData = hex"cafe";
        uint256 deadline = block.timestamp + 1 days;

        bytes memory userSig = _signInstallAndExecute(policyId, executionData, deadline);

        PolicyManager.InstallAndExecutePayload memory payload = PolicyManager.InstallAndExecutePayload({
            binding: binding,
            policyConfig: policyConfig,
            userSig: userSig,
            executionData: executionData,
            deadline: deadline
        });

        policyManager.executeWithInstall(payload);

        assertTrue(policyManager.isPolicyInstalled(address(policy), policyId));
        assertEq(policy.lastExecutedPolicyId(), policyId);
        assertEq(policy.lastCaller(), address(this));
    }

    function test_executeWithInstall_whenAlreadyInstalled_executesWithoutInstallSignature() public {
        bytes memory policyConfig = abi.encode(uint256(111));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 12345,
            policyConfigHash: keccak256(policyConfig)
        });
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);

        PolicyManager.InstallAndExecutePayload memory payload = PolicyManager.InstallAndExecutePayload({
            binding: binding, policyConfig: policyConfig, userSig: "", executionData: hex"abcd", deadline: 0
        });
        policyManager.executeWithInstall(payload);

        assertEq(policy.lastExecutedPolicyId(), policyId);
        assertEq(policy.lastCaller(), address(this));
    }

    function test_installPolicyWithSignature_isIdempotent_noHookNoEventOnSecondCall() public {
        bytes memory policyConfig = abi.encode(uint256(789));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 7,
            policyConfigHash: keccak256(policyConfig)
        });
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        bytes memory userSig = _signInstall(binding);

        vm.recordLogs();
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);
        Vm.Log[] memory entries = vm.getRecordedLogs();

        uint256 installedEvents;
        for (uint256 i = 0; i < entries.length; i++) {
            if (entries[i].topics.length > 0 && entries[i].topics[0] == POLICY_INSTALLED_EVENT_SIG) {
                installedEvents++;
            }
        }

        assertTrue(policyManager.isPolicyInstalled(address(policy), policyId));
        assertEq(policy.installCalls(), 1);
        assertEq(installedEvents, 1);
    }

    function _signInstall(PolicyManager.PolicyBinding memory binding) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getPolicyBindingStructHash(binding);
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    function _signInstallAndExecute(bytes32 policyId, bytes memory executionData, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(policyManager.INSTALL_AND_EXECUTE_TYPEHASH(), policyId, keccak256(executionData), deadline)
        );
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

