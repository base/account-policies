// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {PolicyTypes} from "../src/PolicyTypes.sol";
import {ERC20SpendHook} from "../src/SpendPermissionSpendHooks/ERC20SpendHook.sol";
import {MagicSpendSpendHook} from "../src/SpendPermissionSpendHooks/MagicSpendSpendHook.sol";
import {NativeTokenSpendHook} from "../src/SpendPermissionSpendHooks/NativeTokenSpendHook.sol";
import {SubAccountSpendHook} from "../src/SpendPermissionSpendHooks/SubAccountSpendHook.sol";
import {SpendPolicy} from "../src/policies/SpendPolicy.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";
import {MagicSpend} from "magicspend/MagicSpend.sol";

contract TestToken is ERC20 {
    constructor() ERC20("TestToken", "TST") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract SpendPermissionHookHappyPathTest is Test {
    address internal constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal spenderPk = uint256(keccak256("spender"));
    address internal spender = vm.addr(spenderPk);

    uint256 internal magicSpendOwnerPk = uint256(keccak256("magicSpendOwner"));
    address internal magicSpendOwner = vm.addr(magicSpendOwnerPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    SpendPolicy internal spendPolicy;
    ERC20SpendHook internal erc20SpendHook;
    NativeTokenSpendHook internal nativeTokenSpendHook;
    SubAccountSpendHook internal subAccountSpendHook;
    MagicSpend internal magicSpend;
    MagicSpendSpendHook internal magicSpendSpendHook;
    TestToken internal token;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        spendPolicy = new SpendPolicy(address(policyManager));
        erc20SpendHook = new ERC20SpendHook(address(spendPolicy));
        nativeTokenSpendHook = new NativeTokenSpendHook(address(spendPolicy));
        subAccountSpendHook = new SubAccountSpendHook(address(spendPolicy));
        magicSpend = new MagicSpend(magicSpendOwner, 1);
        magicSpendSpendHook = new MagicSpendSpendHook(address(spendPolicy), address(magicSpend));

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        token = new TestToken();
    }

    function test_spendPermissionHook_happyPath_smartWallet_noBA_erc20() public {
        uint160 allowance = 100 ether;
        uint160 spendValue = 10 ether;

        token.mint(address(account), allowance);
        assertEq(token.balanceOf(address(account)), allowance);

        SpendPolicy.SpendPermission memory sp = SpendPolicy.SpendPermission({
            account: address(account),
            spender: spender,
            token: address(token),
            allowance: allowance,
            period: 7 days,
            start: uint48(block.timestamp),
            end: type(uint48).max,
            salt: 0,
            extraData: hex"",
            spendHook: address(erc20SpendHook),
            spendHookConfig: hex""
        });
        bytes memory policyConfig = abi.encode(sp);

        PolicyTypes.PolicyBinding memory binding = PolicyTypes.PolicyBinding({
            account: address(account),
            policy: address(spendPolicy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 123
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig, false);

        bytes memory policyData = abi.encode(spendValue, bytes(""));

        vm.prank(spender);
        policyManager.execute(binding, policyConfig, policyData);

        assertEq(token.balanceOf(address(account)), allowance - spendValue);
        assertEq(token.balanceOf(spender), spendValue);
    }

    function test_spendPermissionHook_happyPath_smartWallet_nativeETH() public {
        uint160 allowance = 5 ether;
        uint160 spendValue = 1 ether;

        vm.deal(address(account), allowance);
        assertEq(address(account).balance, allowance);
        assertEq(spender.balance, 0);
        assertEq(address(spendPolicy).balance, 0);

        SpendPolicy.SpendPermission memory sp = SpendPolicy.SpendPermission({
            account: address(account),
            spender: spender,
            token: NATIVE_TOKEN,
            allowance: allowance,
            period: 7 days,
            start: uint48(block.timestamp),
            end: type(uint48).max,
            salt: 0,
            extraData: hex"",
            spendHook: address(nativeTokenSpendHook),
            spendHookConfig: hex""
        });
        bytes memory policyConfig = abi.encode(sp);

        PolicyTypes.PolicyBinding memory binding = PolicyTypes.PolicyBinding({
            account: address(account),
            policy: address(spendPolicy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 456
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig, false);

        bytes memory policyData = abi.encode(spendValue, bytes(""));

        vm.prank(spender);
        policyManager.execute(binding, policyConfig, policyData);

        assertEq(address(account).balance, allowance - spendValue);
        assertEq(spender.balance, spendValue);
        assertEq(address(spendPolicy).balance, 0);
    }

    function test_spendPermissionHook_happyPath_smartWallet_subAccount_erc20() public {
        uint160 allowance = 100 ether;
        uint160 spendValue = 10 ether;

        // Sub-account owned by the main account (so main can call subAccount.execute).
        MockCoinbaseSmartWallet subAccount = new MockCoinbaseSmartWallet();
        bytes[] memory subOwners = new bytes[](1);
        subOwners[0] = abi.encode(address(account));
        subAccount.initialize(subOwners);

        token.mint(address(subAccount), allowance);
        assertEq(token.balanceOf(address(subAccount)), allowance);
        assertEq(token.balanceOf(address(account)), 0);

        SpendPolicy.SpendPermission memory sp = SpendPolicy.SpendPermission({
            account: address(account),
            spender: spender,
            token: address(token),
            allowance: allowance,
            period: 7 days,
            start: uint48(block.timestamp),
            end: type(uint48).max,
            salt: 0,
            extraData: hex"",
            spendHook: address(subAccountSpendHook),
            spendHookConfig: abi.encode(address(subAccount))
        });
        bytes memory policyConfig = abi.encode(sp);

        PolicyTypes.PolicyBinding memory binding = PolicyTypes.PolicyBinding({
            account: address(account),
            policy: address(spendPolicy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 777
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig, false);

        bytes memory policyData = abi.encode(spendValue, bytes(""));

        vm.prank(spender);
        policyManager.execute(binding, policyConfig, policyData);

        assertEq(token.balanceOf(address(subAccount)), allowance - spendValue);
        assertEq(token.balanceOf(address(account)), 0);
        assertEq(token.balanceOf(spender), spendValue);
    }

    function test_spendPermissionHook_happyPath_smartWallet_magicSpend_erc20() public {
        uint160 allowance = 100 ether;
        uint160 spendValue = 10 ether;

        // Fund MagicSpend with ERC20 so it can withdraw the token to the account.
        token.mint(address(magicSpend), allowance);
        assertEq(token.balanceOf(address(magicSpend)), allowance);
        assertEq(token.balanceOf(address(account)), 0);

        SpendPolicy.SpendPermission memory sp = SpendPolicy.SpendPermission({
            account: address(account),
            spender: spender,
            token: address(token),
            allowance: allowance,
            period: 7 days,
            start: uint48(block.timestamp),
            end: type(uint48).max,
            salt: 0,
            extraData: hex"",
            spendHook: address(magicSpendSpendHook),
            spendHookConfig: hex""
        });
        bytes memory policyConfig = abi.encode(sp);

        PolicyTypes.PolicyBinding memory binding = PolicyTypes.PolicyBinding({
            account: address(account),
            policy: address(spendPolicy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 888
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig, false);

        // MagicSpendSpendHook binds the withdraw nonce to the low 128 bits of the spend-permission hash.
        bytes32 permissionHash = spendPolicy.getHash(sp);
        uint256 withdrawNonce = uint256(uint128(uint256(permissionHash)));

        MagicSpend.WithdrawRequest memory withdrawRequest = MagicSpend.WithdrawRequest({
            signature: "",
            asset: address(token),
            amount: spendValue,
            nonce: withdrawNonce,
            expiry: uint48(block.timestamp + 1 days)
        });
        bytes32 withdrawDigest = magicSpend.getHash(address(account), withdrawRequest);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(magicSpendOwnerPk, withdrawDigest);
        withdrawRequest.signature = abi.encodePacked(r, s, v);

        bytes memory prepData = abi.encode(withdrawRequest);
        bytes memory policyData = abi.encode(spendValue, prepData);

        vm.prank(spender);
        policyManager.execute(binding, policyConfig, policyData);

        assertEq(token.balanceOf(address(magicSpend)), allowance - spendValue);
        assertEq(token.balanceOf(address(account)), 0);
        assertEq(token.balanceOf(spender), spendValue);
    }

    function _signInstall(PolicyTypes.PolicyBinding memory binding) internal view returns (bytes memory) {
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

