// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {PolicyTypes} from "../src/PolicyTypes.sol";
import {MorphoLendPolicy, MarketParams} from "../src/policies/MorphoLendPolicy.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";
import {MockMorpho} from "./mocks/MockMorpho.sol";

contract MintableToken is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MorphoLendPolicyTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    bytes32 internal constant EXECUTION_TYPEHASH = keccak256(
        "Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash,uint256 nonce)"
    );

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal executorPk = uint256(keccak256("executor"));
    address internal executor = vm.addr(executorPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    MorphoLendPolicy internal policy;
    MockMorpho internal morpho;
    MintableToken internal loanToken;
    MintableToken internal collateralToken;

    MarketParams internal market;
    bytes internal policyConfig;
    PolicyTypes.Install internal install;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new MorphoLendPolicy(address(policyManager));

        // PolicyManager must be an owner to call wallet execution methods.
        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        loanToken = new MintableToken("Loan", "LOAN");
        collateralToken = new MintableToken("Collateral", "COLL");
        morpho = new MockMorpho();

        market = MarketParams({
            loanToken: address(loanToken),
            collateralToken: address(collateralToken),
            oracle: address(0xBEEF),
            irm: address(0xCAFE),
            lltv: 8e17 // 80%
        });

        MorphoLendPolicy.Config memory cfg = MorphoLendPolicy.Config({
            account: address(account),
            executor: executor,
            morpho: address(morpho),
            marketParams: market,
            maxSupply: 1_000_000 ether,
            maxCumulativeSupply: 0
        });

        policyConfig = abi.encode(cfg);
        install = PolicyTypes.Install({
            account: address(account),
            policy: address(policy),
            policyConfigHash: keccak256(policyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 111
        });

        bytes memory userSig = _signInstall(install);
        policyManager.installPolicyWithSignature(install, policyConfig, userSig);
    }

    function test_morphoPolicy_supplyOnly() public {
        uint256 supplyAmt = 100 ether;

        loanToken.mint(address(account), supplyAmt);
        assertEq(loanToken.balanceOf(address(account)), supplyAmt);

        _exec(supplyAmt);
        assertEq(loanToken.balanceOf(address(account)), 0);
        assertEq(loanToken.allowance(address(account), address(morpho)), 0);
    }

    function test_morphoPolicy_enforcesMaxSupply() public {
        MorphoLendPolicy.Config memory cfg = abi.decode(policyConfig, (MorphoLendPolicy.Config));
        cfg.maxSupply = 1 ether;

        bytes memory localPolicyConfig = abi.encode(cfg);
        PolicyTypes.Install memory localInstall = PolicyTypes.Install({
            account: address(account),
            policy: address(policy),
            policyConfigHash: keccak256(localPolicyConfig),
            validAfter: 0,
            validUntil: 0,
            salt: 222
        });

        bytes memory userSig = _signInstall(localInstall);
        policyManager.installPolicyWithSignature(localInstall, localPolicyConfig, userSig);

        loanToken.mint(address(account), 2 ether);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(MorphoLendPolicy.AmountTooHigh.selector, 2 ether, 1 ether));
        policyManager.execute(
            localInstall,
            localPolicyConfig,
            abi.encode(
                MorphoLendPolicy.PolicyData({
                    data: MorphoLendPolicy.LendData({assets: 2 ether, nonce: 1}),
                    signature: bytes("")
                })
            ),
            uint48(block.timestamp + 60)
        );
    }

    function test_morphoPolicy_executorSig_allowsRelayer_andPreventsReplay() public {
        uint256 supplyAmt = 100 ether;
        loanToken.mint(address(account), supplyAmt);

        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: supplyAmt, nonce: 1});
        bytes memory payload = abi.encode(ld);
        uint48 deadline = uint48(block.timestamp + 60);

        bytes32 execDigest = _getPolicyExecutionDigest(install, payload, ld.nonce);
        bytes memory sig = _signExecution(execDigest);
        bytes memory policyData = abi.encode(MorphoLendPolicy.PolicyData({data: ld, signature: sig}));

        address relayer = vm.addr(uint256(keccak256("relayer")));
        vm.prank(relayer);
        policyManager.execute(install, policyConfig, policyData, deadline);

        assertEq(loanToken.balanceOf(address(account)), 0);
        assertEq(loanToken.allowance(address(account), address(morpho)), 0);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MorphoLendPolicy.ExecutionNonceAlreadyUsed.selector, policyManager.getInstallStructHash(install), ld.nonce
            )
        );
        policyManager.execute(install, policyConfig, policyData, deadline);
    }

    function _exec(uint256 assets) internal {
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: assets, nonce: 1});
        vm.prank(executor);
        policyManager.execute(
            install,
            policyConfig,
            abi.encode(MorphoLendPolicy.PolicyData({data: ld, signature: bytes("")})),
            uint48(block.timestamp + 60)
        );
    }

    function _signExecution(bytes32 execDigest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, execDigest);
        return abi.encodePacked(r, s, v);
    }

    function _getPolicyExecutionDigest(
        PolicyTypes.Install memory inst,
        bytes memory payload,
        uint256 nonce
    ) internal view returns (bytes32) {
        bytes32 policyId = policyManager.getInstallStructHash(inst);
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTION_TYPEHASH,
                policyId,
                inst.account,
                inst.policyConfigHash,
                keccak256(payload),
                nonce
            )
        );
        return _hashTypedData(address(policy), "Morpho Lend Policy", "1", structHash);
    }

    function _signInstall(PolicyTypes.Install memory inst) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getInstallStructHash(inst);
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

