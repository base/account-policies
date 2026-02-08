// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../src/PolicyManager.sol";
import {Policy} from "../../../src/policies/Policy.sol";

import {MockCoinbaseSmartWallet} from "../../lib/mocks/MockCoinbaseSmartWallet.sol";

contract CancelNoopPolicy is Policy {
    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32, address, bytes calldata, address) internal override {}

    function _onUninstall(bytes32, address, bytes calldata, bytes calldata, address) internal override {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        override
        returns (bytes memory, bytes memory)
    {
        return ("", "");
    }
}

/// @title CancelPolicyTest
///
/// @notice Tests for `PolicyManager.cancelPolicy` (pre-install and post-install paths).
contract CancelPolicyTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    CancelNoopPolicy internal policy;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new CancelNoopPolicy(address(policyManager));

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));
    }

    function test_cancelPolicy_preInstall_blocksFutureInstall() public {
        bytes memory policyConfig = abi.encode(uint256(123));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 777,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        vm.prank(address(account));
        policyManager.cancelPolicy(binding, policyConfig, "");

        bytes memory userSig = _signInstall(binding);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, policyId));
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);
    }

    function test_cancelPolicy_afterInstall_uninstallsNormally() public {
        bytes memory policyConfig = abi.encode(uint256(456));

        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 888,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));

        vm.prank(address(account));
        policyManager.cancelPolicy(binding, policyConfig, "");

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
        assertFalse(policyManager.isPolicyActive(address(policy), policyId));
    }

    function _signInstall(PolicyManager.PolicyBinding memory binding) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getPolicyBindingStructHash(binding);
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

