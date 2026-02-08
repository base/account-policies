// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../src/PolicyManager.sol";

import {CallForwardingPolicy} from "./policies/CallForwardingPolicy.sol";
import {CallReceiver} from "./mocks/CallReceiver.sol";
import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";

/// @title PolicyManagerTestBase
///
/// @notice Shared fixture + helpers for `PolicyManager` unit tests.
abstract contract PolicyManagerTestBase is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;

    CallForwardingPolicy internal callPolicy;
    CallReceiver internal receiver;

    function setUpPolicyManagerBase() public virtual {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);

        callPolicy = new CallForwardingPolicy(address(policyManager));
        receiver = new CallReceiver();

        // PolicyManager must be an owner to call wallet execution methods.
        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        vm.label(address(account), "Account");
        vm.label(address(policyManager), "PolicyManager");
        vm.label(address(validator), "PublicERC6492Validator");
        vm.label(address(callPolicy), "CallForwardingPolicy");
        vm.label(address(receiver), "CallReceiver");
        vm.label(owner, "Owner");
    }

    function _binding(address policy, bytes memory policyConfig, uint256 salt)
        internal
        view
        returns (PolicyManager.PolicyBinding memory binding)
    {
        binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: policy,
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfigHash: keccak256(policyConfig)
        });
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

