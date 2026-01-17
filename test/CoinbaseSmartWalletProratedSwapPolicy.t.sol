// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {PermissionTypes} from "../src/PermissionTypes.sol";
import {CoinbaseSmartWalletProratedSwapPolicy} from "../src/policies/CoinbaseSmartWalletProratedSwapPolicy.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";
import {MockSwapTarget} from "./mocks/MockSwapTarget.sol";

contract TestToken is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract CoinbaseSmartWalletProratedSwapPolicyTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal authorityPk = uint256(keccak256("authority"));
    address internal authority = vm.addr(authorityPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal pm;
    CoinbaseSmartWalletProratedSwapPolicy internal policy;
    MockSwapTarget internal swapTarget;

    TestToken internal tokenIn;
    TestToken internal tokenOut;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        pm = new PolicyManager(validator);
        policy = new CoinbaseSmartWalletProratedSwapPolicy(address(pm));
        swapTarget = new MockSwapTarget();

        vm.prank(owner);
        account.addOwnerAddress(address(pm));

        tokenIn = new TestToken("TokenIn", "TIN");
        tokenOut = new TestToken("TokenOut", "TOUT");
    }

    function test_proratedMinOut_happyPath() public {
        uint256 maxAmountIn = 10 ether;
        uint256 minOutForMax = 3 ether;

        uint256 amountIn = 5 ether; // half
        uint256 expectedMinOut = 1.5 ether; // half
        uint256 amountOut = 2 ether; // >= expectedMinOut

        tokenIn.mint(address(account), amountIn);
        tokenOut.mint(address(swapTarget), amountOut);

        CoinbaseSmartWalletProratedSwapPolicy.Config memory cfg = CoinbaseSmartWalletProratedSwapPolicy.Config({
            account: address(account),
            authority: authority,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            swapTarget: address(swapTarget),
            swapSelector: MockSwapTarget.swap.selector,
            maxAmountIn: maxAmountIn,
            minAmountOutForMaxAmountIn: minOutForMax,
            validAfter: 0,
            validUntil: 0
        });
        bytes memory policyConfig = abi.encode(cfg);

        PermissionTypes.Install memory install = PermissionTypes.Install({
            account: address(account),
            policy: address(policy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 123
        });

        bytes memory userSig = _signInstall(install);
        pm.installPolicyWithSignature(install, policyConfig, userSig);

        bytes memory swapData = abi.encodeWithSelector(
            MockSwapTarget.swap.selector, address(tokenIn), address(tokenOut), address(account), amountIn, amountOut
        );
        bytes memory policyData =
            abi.encode(CoinbaseSmartWalletProratedSwapPolicy.PolicyData({amountIn: amountIn, swapData: swapData}));

        uint256 beforeOut = tokenOut.balanceOf(address(account));
        vm.prank(authority);
        pm.execute(install, policyConfig, policyData, 1, uint48(block.timestamp + 60), hex"");
        uint256 afterOut = tokenOut.balanceOf(address(account));

        assertEq(afterOut - beforeOut, amountOut);
        assertTrue(afterOut - beforeOut >= expectedMinOut);
        assertEq(IERC20(address(tokenIn)).allowance(address(account), address(swapTarget)), 0);
    }

    function test_proratedMinOut_revertsWhenBelowProrated() public {
        uint256 maxAmountIn = 10 ether;
        uint256 minOutForMax = 3 ether;

        uint256 amountIn = 5 ether; // half
        uint256 expectedMinOut = 1.5 ether; // half
        uint256 amountOut = 1 ether; // < expectedMinOut

        tokenIn.mint(address(account), amountIn);
        tokenOut.mint(address(swapTarget), amountOut);

        CoinbaseSmartWalletProratedSwapPolicy.Config memory cfg = CoinbaseSmartWalletProratedSwapPolicy.Config({
            account: address(account),
            authority: authority,
            tokenIn: address(tokenIn),
            tokenOut: address(tokenOut),
            swapTarget: address(swapTarget),
            swapSelector: MockSwapTarget.swap.selector,
            maxAmountIn: maxAmountIn,
            minAmountOutForMaxAmountIn: minOutForMax,
            validAfter: 0,
            validUntil: 0
        });
        bytes memory policyConfig = abi.encode(cfg);

        PermissionTypes.Install memory install = PermissionTypes.Install({
            account: address(account),
            policy: address(policy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 456
        });

        bytes memory userSig = _signInstall(install);
        pm.installPolicyWithSignature(install, policyConfig, userSig);

        bytes memory swapData = abi.encodeWithSelector(
            MockSwapTarget.swap.selector, address(tokenIn), address(tokenOut), address(account), amountIn, amountOut
        );
        bytes memory policyData =
            abi.encode(CoinbaseSmartWalletProratedSwapPolicy.PolicyData({amountIn: amountIn, swapData: swapData}));

        vm.prank(authority);
        bytes memory innerError = abi.encodeWithSelector(
            CoinbaseSmartWalletProratedSwapPolicy.TokenOutBalanceTooLow.selector, 0, amountOut, expectedMinOut
        );
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.AccountCallFailed.selector, address(policy), innerError));
        pm.execute(install, policyConfig, policyData, 1, uint48(block.timestamp + 60), hex"");
    }

    function _signInstall(PermissionTypes.Install memory install) internal view returns (bytes memory) {
        bytes32 structHash = pm.getInstallStructHash(install);
        bytes32 digest = _hashTypedData(address(pm), "Policy Manager", "1", structHash);
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

