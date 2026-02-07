// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {Policy} from "../src/policies/Policy.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";

/// @title ReplaceNoopPolicy
///
/// @notice Minimal test policy used for replace-policy tests.
contract ReplaceNoopPolicy is Policy {
    mapping(bytes32 policyId => bytes32 configHash) internal _configHash;

    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    /// @notice Constructs the test policy.
    ///
    /// @param policyManager Policy manager address.
    constructor(address policyManager) Policy(policyManager) {}

    /// @dev Stores a config hash so executes can validate preimages.
    function _onInstall(bytes32 policyId, address, bytes calldata policyConfig, address) internal override {
        _configHash[policyId] = keccak256(policyConfig);
    }

    /// @dev No-op uninstall hook for tests.
    function _onUninstall(bytes32, address, bytes calldata, bytes calldata, address) internal override {}

    /// @dev Validates config hash (used in other tests that execute under this policy).
    function _onExecute(bytes32 policyId, address, bytes calldata policyConfig, bytes calldata, address)
        internal
        override
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        bytes32 expected = _configHash[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);
        return ("", "");
    }
}

/// @title PolicyManagerReplaceTest
///
/// @notice Tests for `PolicyManager.replacePolicyWithSignature`.
contract PolicyManagerReplaceTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    ReplaceNoopPolicy internal policy;

    /// @notice Test fixture setup.
    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new ReplaceNoopPolicy(address(policyManager));

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));
    }

    /// @notice Atomically uninstalls an old policyId and installs a new policyId via an account signature.
    function test_replacePolicyWithSignature_uninstallsOldAndInstallsNew() public {
        bytes memory oldConfig = abi.encode(uint256(1));
        PolicyManager.PolicyBinding memory oldBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 111,
            policyConfigHash: keccak256(oldConfig)
        });
        bytes32 oldPolicyId = policyManager.getPolicyBindingStructHash(oldBinding);
        bytes memory installSig = _signInstall(oldBinding);
        policyManager.installPolicyWithSignature(oldBinding, oldConfig, installSig);

        bytes memory newConfig = abi.encode(uint256(2));
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 222,
            policyConfigHash: keccak256(newConfig)
        });
        bytes32 newPolicyId = policyManager.getPolicyBindingStructHash(newBinding);

        uint256 deadline = block.timestamp + 1 days;
        bytes memory replaceSig = _signReplace(address(policy), oldPolicyId, newPolicyId, deadline);

        PolicyManager.ReplacePolicyPayload memory payload = PolicyManager.ReplacePolicyPayload({
            oldPolicy: address(policy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: "",
            newBinding: newBinding,
            newPolicyConfig: newConfig,
            userSig: replaceSig,
            deadline: deadline
        });

        address relayer = vm.addr(uint256(keccak256("relayer")));
        vm.prank(relayer);
        policyManager.replacePolicyWithSignature(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), oldPolicyId));
        assertTrue(policyManager.isPolicyInstalled(address(policy), newPolicyId));
        assertFalse(policyManager.isPolicyUninstalled(address(policy), newPolicyId));
    }

    /// @dev Signs a binding struct hash for `installPolicyWithSignature`.
    function _signInstall(PolicyManager.PolicyBinding memory binding) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getPolicyBindingStructHash(binding);
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    /// @dev Signs a replace-policy typed message for `replacePolicyWithSignature`.
    function _signReplace(address oldPolicy, bytes32 oldPolicyId, bytes32 newPolicyId, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                policyManager.REPLACE_POLICY_TYPEHASH(),
                address(account),
                oldPolicy,
                oldPolicyId,
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

    /// @dev Computes an EIP-712 typed data digest for tests.
    function _hashTypedData(address verifyingContract, string memory name, string memory version, bytes32 structHash)
        internal
        view
        returns (bytes32)
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, verifyingContract)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}

