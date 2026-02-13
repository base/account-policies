// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PublicERC6492Validator} from "../../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";

import {MockCoinbaseSmartWallet} from "../../mocks/MockCoinbaseSmartWallet.sol";

/// @notice Minimal AOA policy used for testing shared AOA behaviors.
contract AOATestPolicy is AOAPolicy {
    constructor(address policyManager, address admin) AOAPolicy(policyManager, admin) {}

    function _onAOAExecute(bytes32, AOAConfig memory, bytes memory, bytes memory)
        internal
        pure
        override
        returns (bytes memory, bytes memory)
    {
        return ("", "");
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "AOA Test Policy";
        version = "1";
    }
}

/// @title AOAPolicyTestBase
///
/// @notice Shared fixture for testing AOA wrapper semantics (pause/uninstall).
abstract contract AOAPolicyTestBase is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    uint256 internal constant DEFAULT_SALT = 1;

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
        setUpAOABaseWithSalt(DEFAULT_SALT);
    }

    function setUpAOABaseWithSalt(uint256 salt) internal {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new AOATestPolicy(address(policyManager), owner);

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        policyConfig = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), bytes(""));
        binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installWithSignature(binding, policyConfig, userSig, bytes(""));
    }

    function _signInstall(PolicyManager.PolicyBinding memory binding_) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getPolicyId(binding_);
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

