// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {Id, Market, MarketParams, Position} from "../src/interfaces/morpho/BlueTypes.sol";
import {MorphoLoanProtectionPolicy} from "../src/policies/MorphoLoanProtectionPolicy.sol";
import {RecurringAllowance} from "../src/policies/accounting/RecurringAllowance.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";
import {MockMorphoBlue, MockMorphoOracle} from "./mocks/MockMorphoBlue.sol";

contract MintableToken is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MorphoLoanProtectionPolicyTest is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal executorPk = uint256(keccak256("executor"));
    address internal executor = vm.addr(executorPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    MorphoLoanProtectionPolicy internal policy;

    MockMorphoBlue internal morpho;
    MockMorphoOracle internal oracle;
    MintableToken internal loanToken;
    MintableToken internal collateralToken;

    Id internal marketId;
    MarketParams internal marketParams;
    bytes internal policyConfig;
    PolicyManager.PolicyBinding internal binding;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new MorphoLoanProtectionPolicy(address(policyManager));

        // PolicyManager must be an owner to call wallet execution methods.
        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        loanToken = new MintableToken("Loan", "LOAN");
        collateralToken = new MintableToken("Collateral", "COLL");

        morpho = new MockMorphoBlue();
        oracle = new MockMorphoOracle();
        oracle.setPrice(1e36); // 1 collateral token == 1 loan token (scaled by 1e36)

        marketId = Id.wrap(bytes32(uint256(123)));
        marketParams = MarketParams({
            loanToken: address(loanToken),
            collateralToken: address(collateralToken),
            oracle: address(oracle),
            irm: address(0xBEEF),
            lltv: 0.8e18
        });

        morpho.setMarket(
            marketId,
            marketParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: uint128(1e18),
                totalBorrowShares: uint128(1e18),
                lastUpdate: 0,
                fee: 0
            })
        );

        // Default position: debt = 75, collateral = 100 => LTV = 75%
        morpho.setPosition(
            marketId,
            address(account),
            Position({supplyShares: 0, borrowShares: uint128(75 ether), collateral: uint128(100 ether)})
        );

        // Fund wallet with collateral for top-ups.
        collateralToken.mint(address(account), 1_000 ether);

        MorphoLoanProtectionPolicy.Config memory cfg = MorphoLoanProtectionPolicy.Config({
            executor: executor,
            morpho: address(morpho),
            marketId: marketId,
            marketParams: marketParams,
            triggerLtv: 0.70e18,
            minPostProtectionLtv: 0.45e18,
            maxPostProtectionLtv: 0.60e18,
            collateralLimit: RecurringAllowance.Limit({
                allowance: 500 ether,
                period: 7 days,
                start: uint48(block.timestamp),
                end: type(uint48).max
            })
        });
        policyConfig = abi.encode(cfg);

        binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 111,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);
    }

    function test_happyPath_topUpCollateral_enforcesLtvBounds_andResetsApproval() public {
        uint256 topUp = 50 ether; // projected LTV = 75 / 150 = 50%
        bytes memory policyData = _encodePolicyData(topUp, 1, uint256(block.timestamp + 1 days), hex"");

        address relayer = vm.addr(uint256(keccak256("relayer")));
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        vm.prank(relayer);
        policyManager.execute(address(policy), policyId, policyConfig, policyData);

        Position memory p = morpho.position(marketId, address(account));
        assertEq(uint256(p.collateral), 150 ether);
        assertEq(collateralToken.allowance(address(account), address(morpho)), 0);
    }

    function test_revertsWhenHealthy_belowTrigger() public {
        // Make position safer: debt=50, collateral=100 => LTV=50% < trigger 70%
        morpho.setPosition(
            marketId,
            address(account),
            Position({supplyShares: 0, borrowShares: uint128(50 ether), collateral: uint128(100 ether)})
        );

        bytes memory policyData = _encodePolicyData(10 ether, 1, uint256(block.timestamp + 1 days), hex"");
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        vm.expectRevert(); // HealthyPosition(...)
        vm.prank(vm.addr(uint256(keccak256("relayer"))));
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_revertsWhenProjectedLtvStillTooHigh_underProtect() public {
        // Top up too small: debt=75, collateral=100+10 => LTV ~ 68.18% > maxPost 60%
        bytes memory policyData = _encodePolicyData(10 ether, 1, uint256(block.timestamp + 1 days), hex"");
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        vm.expectRevert(); // ProjectedLtvTooHigh(...)
        vm.prank(vm.addr(uint256(keccak256("relayer"))));
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_revertsWhenProjectedLtvTooLow_overProtect() public {
        // Top up too large: debt=75, collateral=100+200 => LTV=25% < minPost 45%
        bytes memory policyData = _encodePolicyData(200 ether, 1, uint256(block.timestamp + 1 days), hex"");
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        vm.expectRevert(); // ProjectedLtvTooLow(...)
        vm.prank(vm.addr(uint256(keccak256("relayer"))));
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_revertsOnNonceReplay() public {
        uint256 topUp = 50 ether;
        bytes memory policyData = _encodePolicyData(topUp, 1, uint256(block.timestamp + 1 days), hex"");
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        vm.prank(vm.addr(uint256(keccak256("relayer"))));
        policyManager.execute(address(policy), policyId, policyConfig, policyData);

        vm.expectRevert(); // ExecutionNonceAlreadyUsed(...)
        vm.prank(vm.addr(uint256(keccak256("relayer"))));
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_onePolicyPerMarket_enforced_andRevocationUnlocks() public {
        // Attempt to install another policy instance for the same (account, market).
        MorphoLoanProtectionPolicy.Config memory cfg = abi.decode(policyConfig, (MorphoLoanProtectionPolicy.Config));
        bytes memory cfg2 = abi.encode(cfg);
        PolicyManager.PolicyBinding memory binding2 = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 222,
            policyConfigHash: keccak256(cfg2)
        });

        bytes memory userSig2 = _signInstall(binding2);
        vm.expectRevert(); // PolicyAlreadyInstalledForMarket(...)
        policyManager.installPolicyWithSignature(binding2, cfg2, userSig2);

        // Revoke and then install should succeed.
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        vm.prank(address(account));
        policyManager.uninstallPolicy(address(policy), policyId);

        policyManager.installPolicyWithSignature(binding2, cfg2, userSig2);
    }

    function _encodePolicyData(uint256 topUp, uint256 nonce, uint256 deadline, bytes memory callbackData)
        internal
        view
        returns (bytes memory)
    {
        return _encodePolicyDataLocal(binding, policyConfig, topUp, nonce, deadline, callbackData);
    }

    function _encodePolicyDataLocal(
        PolicyManager.PolicyBinding memory binding_,
        bytes memory policyConfig_,
        uint256 topUp,
        uint256 nonce,
        uint256 deadline,
        bytes memory callbackData
    ) internal view returns (bytes memory) {
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding_);
        bytes32 configHash = keccak256(policyConfig_);

        bytes32 callbackHash = keccak256(callbackData);
        bytes32 protectHash = keccak256(
            abi.encode(policy.TOP_UP_DATA_TYPEHASH(), topUp, nonce, deadline, callbackHash)
        );
        bytes32 structHash = keccak256(
            abi.encode(policy.EXECUTION_TYPEHASH(), policyId, address(account), configHash, protectHash)
        );
        bytes32 digest = _hashTypedData(address(policy), "Morpho Loan Protection Policy", "1", structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        MorphoLoanProtectionPolicy.TopUpData memory pd = MorphoLoanProtectionPolicy.TopUpData({
            topUpAssets: topUp,
            nonce: nonce,
            deadline: deadline,
            callbackData: callbackData
        });
        return abi.encode(MorphoLoanProtectionPolicy.PolicyData({data: pd, signature: sig}));
    }

    function _signInstall(PolicyManager.PolicyBinding memory binding_) internal view returns (bytes memory) {
        bytes32 structHash = policyManager.getPolicyBindingStructHash(binding_);
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

