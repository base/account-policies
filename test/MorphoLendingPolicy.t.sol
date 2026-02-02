// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../src/policies/MorphoLendPolicy.sol";
import {AOAPolicy} from "../src/policies/AOAPolicy.sol";
import {RecurringAllowance} from "../src/policies/accounting/RecurringAllowance.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {MockCoinbaseSmartWallet} from "./mocks/MockCoinbaseSmartWallet.sol";
import {MockMorphoVault} from "./mocks/MockMorpho.sol";

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
        "Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash)"
    );

    uint256 internal ownerPk = uint256(keccak256("owner"));
    address internal owner = vm.addr(ownerPk);
    uint256 internal executorPk = uint256(keccak256("executor"));
    address internal executor = vm.addr(executorPk);

    MockCoinbaseSmartWallet internal account;
    PublicERC6492Validator internal validator;
    PolicyManager internal policyManager;
    MorphoLendPolicy internal policy;
    MockMorphoVault internal vault;
    MintableToken internal loanToken;
    bytes internal policyConfig;
    PolicyManager.PolicyBinding internal binding;

    function setUp() public {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new MorphoLendPolicy(address(policyManager), owner);

        // PolicyManager must be an owner to call wallet execution methods.
        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        loanToken = new MintableToken("Loan", "LOAN");
        vault = new MockMorphoVault(address(loanToken));

        bytes memory policySpecificConfig = abi.encode(
            MorphoLendPolicy.MorphoConfig({
                vault: address(vault),
                depositLimit: RecurringAllowance.Limit({allowance: 1_000_000 ether, period: 1 days, start: 0, end: 0})
            })
        );
        policyConfig = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), policySpecificConfig);

        PolicyManager.PolicyBinding memory binding_ = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 111,
            policyConfigHash: keccak256(policyConfig)
        });
        binding = binding_;

        bytes memory userSig = _signInstall(binding);
        policyManager.installPolicyWithSignature(binding, policyConfig, userSig);
    }

    function _decodePolicyConfig(bytes memory policyConfig_)
        internal
        pure
        returns (AOAPolicy.AOAConfig memory aoa, MorphoLendPolicy.MorphoConfig memory cfg)
    {
        bytes memory policySpecificConfig;
        (aoa, policySpecificConfig) = abi.decode(policyConfig_, (AOAPolicy.AOAConfig, bytes));
        cfg = abi.decode(policySpecificConfig, (MorphoLendPolicy.MorphoConfig));
    }

    function _encodePolicyConfig(AOAPolicy.AOAConfig memory aoa, MorphoLendPolicy.MorphoConfig memory cfg)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(aoa, abi.encode(cfg));
    }

    // (Old config constructor removed; policyConfig/binding now built above.)
    /*
        MorphoLendPolicy.Config memory cfg = MorphoLendPolicy.Config({
            executor: executor,
            vault: address(vault),
            depositLimit: RecurringAllowance.Limit({
                allowance: 1_000_000 ether,
                period: 1 days,
                start: 0,
                end: 0
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

    */

    function test_morphoPolicy_supplyOnly() public {
        uint256 supplyAmt = 100 ether;

        loanToken.mint(address(account), supplyAmt);
        assertEq(loanToken.balanceOf(address(account)), supplyAmt);

        // Ergonomics: observe recurring allowance state before/after execution.
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        (RecurringAllowance.PeriodUsage memory lastBefore, RecurringAllowance.PeriodUsage memory currentBefore) =
            policy.getDepositLimitPeriodUsage(policyId, address(account), policyConfig);
        assertEq(lastBefore.spend, 0);
        assertEq(currentBefore.spend, 0);

        _exec(supplyAmt);
        assertEq(loanToken.balanceOf(address(account)), 0);
        assertEq(loanToken.allowance(address(account), address(vault)), 0);

        (RecurringAllowance.PeriodUsage memory lastAfter, RecurringAllowance.PeriodUsage memory currentAfter) =
            policy.getDepositLimitPeriodUsage(policyId, address(account), policyConfig);
        assertEq(lastAfter.spend, uint160(supplyAmt));
        assertEq(currentAfter.spend, uint160(supplyAmt));
    }

    function test_morphoPolicy_enforcesRecurringLimit() public {
        (AOAPolicy.AOAConfig memory aoa, MorphoLendPolicy.MorphoConfig memory cfg) = _decodePolicyConfig(policyConfig);
        cfg.depositLimit.allowance = 1 ether;
        bytes memory localPolicyConfig = _encodePolicyConfig(aoa, cfg);
        PolicyManager.PolicyBinding memory localBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 222,
            policyConfigHash: keccak256(localPolicyConfig)
        });

        bytes memory userSig = _signInstall(localBinding);
        policyManager.installPolicyWithSignature(localBinding, localPolicyConfig, userSig);

        loanToken.mint(address(account), 2 ether);

        bytes32 policyId = policyManager.getPolicyBindingStructHash(localBinding);
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: 2 ether, nonce: 1});
        bytes memory execPolicyData = _encodePolicyDataWithSig(localBinding, ld);
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 2 ether, 1 ether));
        policyManager.execute(address(policy), policyId, localPolicyConfig, execPolicyData);
    }

    function test_morphoPolicy_recurringLimit_resetsNextPeriod() public {
        (AOAPolicy.AOAConfig memory aoa, MorphoLendPolicy.MorphoConfig memory cfg) = _decodePolicyConfig(policyConfig);
        cfg.depositLimit.allowance = 100 ether;
        cfg.depositLimit.period = 1 days;
        cfg.depositLimit.start = 0;
        cfg.depositLimit.end = 0;

        bytes memory localPolicyConfig = _encodePolicyConfig(aoa, cfg);
        PolicyManager.PolicyBinding memory localBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 9999,
            policyConfigHash: keccak256(localPolicyConfig)
        });

        bytes memory userSig = _signInstall(localBinding);
        policyManager.installPolicyWithSignature(localBinding, localPolicyConfig, userSig);

        bytes32 policyId = policyManager.getPolicyBindingStructHash(localBinding);

        loanToken.mint(address(account), 200 ether);

        // First period: spend 60, then try to spend 50 (should exceed 100).
        vm.prank(executor);
        policyManager.execute(
            address(policy),
            policyId,
            localPolicyConfig,
            _encodePolicyDataWithSig(localBinding, MorphoLendPolicy.LendData({assets: 60 ether, nonce: 1}))
        );

        bytes memory execPolicyData2 =
            _encodePolicyDataWithSig(localBinding, MorphoLendPolicy.LendData({assets: 50 ether, nonce: 2}));
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 110 ether, 100 ether));
        policyManager.execute(address(policy), policyId, localPolicyConfig, execPolicyData2);

        // Next period: spend succeeds again.
        vm.warp(block.timestamp + 1 days);
        vm.prank(executor);
        policyManager.execute(
            address(policy),
            policyId,
            localPolicyConfig,
            _encodePolicyDataWithSig(localBinding, MorphoLendPolicy.LendData({assets: 50 ether, nonce: 3}))
        );
    }

    function test_morphoPolicy_executeByPolicyId_usesStoredConfig() public {
        bytes memory storedPolicyConfig = policyConfig;
        PolicyManager.PolicyBinding memory storedBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 333,
            policyConfigHash: keccak256(storedPolicyConfig)
        });
        bytes32 policyId = policyManager.getPolicyBindingStructHash(storedBinding);

        bytes memory userSig = _signInstall(storedBinding);
        policyManager.installPolicyWithSignature(storedBinding, storedPolicyConfig, userSig);

        uint256 supplyAmt = 100 ether;
        loanToken.mint(address(account), supplyAmt);

        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: supplyAmt, nonce: 1});
        bytes memory policyData = _encodePolicyDataWithSig(storedBinding, ld);

        vm.prank(executor);
        policyManager.execute(address(policy), policyId, storedPolicyConfig, policyData);

        assertEq(loanToken.balanceOf(address(account)), 0);
        assertEq(loanToken.allowance(address(account), address(vault)), 0);
    }

    function test_morphoPolicy_reinstallWithSignature_isIdempotent() public {
        bytes memory localPolicyConfig = policyConfig;
        PolicyManager.PolicyBinding memory localBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 444,
            policyConfigHash: keccak256(localPolicyConfig)
        });
        bytes32 policyId = policyManager.getPolicyBindingStructHash(localBinding);

        bytes memory userSig = _signInstall(localBinding);
        bytes32 first = policyManager.installPolicyWithSignature(localBinding, localPolicyConfig, userSig);
        bytes32 second = policyManager.installPolicyWithSignature(localBinding, localPolicyConfig, userSig);

        assertEq(first, policyId);
        assertEq(second, policyId);
        assertTrue(policyManager.isPolicyInstalled(address(policy), policyId));
    }

    function test_morphoPolicy_reinstallDirect_isIdempotent() public {
        bytes memory localPolicyConfig = policyConfig;
        PolicyManager.PolicyBinding memory localBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 555,
            policyConfigHash: keccak256(localPolicyConfig)
        });
        bytes32 policyId = policyManager.getPolicyBindingStructHash(localBinding);

        vm.prank(address(account));
        bytes32 first = policyManager.installPolicy(localBinding, localPolicyConfig);

        vm.prank(address(account));
        bytes32 second = policyManager.installPolicy(localBinding, localPolicyConfig);

        assertEq(first, policyId);
        assertEq(second, policyId);
        assertTrue(policyManager.isPolicyInstalled(address(policy), policyId));
    }

    function test_morphoPolicy_executorCanUninstall() public {
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        vm.prank(executor);
        policyManager.uninstallPolicy(address(policy), policyId, policyConfig, "");

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));

        // Execution should now be blocked by the manager.
        loanToken.mint(address(account), 1 ether);
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: 1 ether, nonce: 1});
        bytes memory policyData = _encodePolicyDataWithSig(binding, ld);
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsUninstalled.selector, policyId));
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_morphoPolicy_executorSig_allowsRelayedUninstall() public {
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);

        uint256 deadline = block.timestamp + 1 days;
        bytes32 structHash =
            keccak256(abi.encode(policy.AOA_UNINSTALL_TYPEHASH(), policyId, address(account), keccak256(policyConfig), deadline));
        bytes32 digest = _hashTypedData(address(policy), "Morpho Lend Policy", "1", structHash);
        bytes memory sig = _signExecution(digest);

        bytes memory uninstallData = abi.encode(sig, deadline);

        address relayer = vm.addr(uint256(keccak256("relayer")));
        vm.prank(relayer);
        policyManager.uninstallPolicy(address(policy), policyId, policyConfig, uninstallData);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    function test_morphoPolicy_pause_blocksExecute() public {
        vm.prank(owner);
        policy.pause();

        loanToken.mint(address(account), 1 ether);
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: 1 ether, nonce: 1});
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        bytes memory policyData = _encodePolicyDataWithSig(binding, ld);

        vm.prank(executor);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_morphoPolicy_executorSig_allowsRelayer_andPreventsReplay() public {
        uint256 supplyAmt = 100 ether;
        loanToken.mint(address(account), supplyAmt);

        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: supplyAmt, nonce: 1});
        bytes memory payload = abi.encode(ld);
        bytes32 execDigest = _getPolicyExecutionDigest(binding, payload);
        bytes memory sig = _signExecution(execDigest);
        bytes memory policyData = abi.encode(abi.encode(ld), sig);

        address relayer = vm.addr(uint256(keccak256("relayer")));
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        vm.prank(relayer);
        policyManager.execute(address(policy), policyId, policyConfig, policyData);

        assertEq(loanToken.balanceOf(address(account)), 0);
        assertEq(loanToken.allowance(address(account), address(vault)), 0);

        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(
                MorphoLendPolicy.ExecutionNonceAlreadyUsed.selector,
                policyId,
                ld.nonce
            )
        );
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function test_morphoPolicy_executorCanPreCancelInstallIntent() public {
        bytes memory localPolicyConfig = policyConfig;
        PolicyManager.PolicyBinding memory localBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 9090,
            policyConfigHash: keccak256(localPolicyConfig)
        });
        bytes32 policyId = policyManager.getPolicyBindingStructHash(localBinding);

        // Executor can cancel an uninstalled policyId (preemptively) by presenting the config.
        vm.prank(executor);
        policyManager.cancelPolicy(localBinding, localPolicyConfig, "");

        // Now installation of that exact policyId is blocked.
        bytes memory userSig = _signInstall(localBinding);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsUninstalled.selector, policyId));
        policyManager.installPolicyWithSignature(localBinding, localPolicyConfig, userSig);
    }

    function _exec(uint256 assets) internal {
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({assets: assets, nonce: 1});
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding);
        bytes memory policyData = _encodePolicyDataWithSig(binding, ld);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function _encodePolicyDataWithSig(PolicyManager.PolicyBinding memory binding_, MorphoLendPolicy.LendData memory ld)
        internal
        view
        returns (bytes memory)
    {
        bytes32 execDigest = _getPolicyExecutionDigest(binding_, abi.encode(ld));
        bytes memory sig = _signExecution(execDigest);
        return abi.encode(abi.encode(ld), sig);
    }

    function _signExecution(bytes32 execDigest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, execDigest);
        return abi.encodePacked(r, s, v);
    }

    function _getPolicyExecutionDigest(PolicyManager.PolicyBinding memory binding_, bytes memory payload)
        internal
        view
        returns (bytes32)
    {
        bytes32 policyId = policyManager.getPolicyBindingStructHash(binding_);
        bytes32 structHash = keccak256(
            abi.encode(
                EXECUTION_TYPEHASH,
                policyId,
                binding_.account,
                binding_.policyConfigHash,
                keccak256(payload)
            )
        );
        return _hashTypedData(address(policy), "Morpho Lend Policy", "1", structHash);
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

