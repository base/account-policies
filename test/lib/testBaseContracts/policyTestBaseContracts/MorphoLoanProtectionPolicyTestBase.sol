// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import {PublicERC6492Validator} from "../../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {Id, Market, MarketParams, Position} from "../../../../src/interfaces/morpho/BlueTypes.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";
import {MockCoinbaseSmartWallet} from "../../mocks/MockCoinbaseSmartWallet.sol";
import {MockMorphoBlue, MockMorphoOracle} from "../../mocks/MockMorphoBlue.sol";

contract MintableToken is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @title MorphoLoanProtectionPolicyTestBase
///
/// @notice Shared fixture + helpers for `MorphoLoanProtectionPolicy` unit tests.
abstract contract MorphoLoanProtectionPolicyTestBase is Test {
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

    function setUpMorphoLoanProtectionBase() internal {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);

        morpho = new MockMorphoBlue();
        oracle = new MockMorphoOracle();

        policy = new MorphoLoanProtectionPolicy(address(policyManager), owner, address(morpho));

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        loanToken = new MintableToken("Loan", "LOAN");
        collateralToken = new MintableToken("Collateral", "COLL");
        oracle.setPrice(1e36);

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

        morpho.setPosition(
            marketId,
            address(account),
            Position({supplyShares: 0, borrowShares: uint128(75 ether), collateral: uint128(100 ether)})
        );

        collateralToken.mint(address(account), 1_000 ether);

        bytes memory policySpecificConfig = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        policyConfig =
            abi.encode(AOAPolicy.AOAConfig({executor: executor}), policySpecificConfig);

        binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: 0,
            policyConfigHash: keccak256(policyConfig)
        });

        bytes memory userSig = _signInstall(binding);
        policyManager.installWithSignature(binding, policyConfig, userSig, bytes(""));
    }

    function _decodePolicyConfig(bytes memory policyConfig_)
        internal
        pure
        returns (AOAPolicy.AOAConfig memory aoa, MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig memory cfg)
    {
        bytes memory policySpecificConfig;
        (aoa, policySpecificConfig) = abi.decode(policyConfig_, (AOAPolicy.AOAConfig, bytes));
        cfg = abi.decode(policySpecificConfig, (MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig));
    }

    function _signReplace(address oldPolicy, bytes32 oldPolicyId, bytes32 newPolicyId, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                policyManager.REPLACE_POLICY_TYPEHASH(), address(account), oldPolicy, oldPolicyId, newPolicyId, deadline
            )
        );
        bytes32 digest = _hashTypedData(address(policyManager), "Policy Manager", "1", structHash);
        bytes32 replaySafeDigest = account.replaySafeHash(digest);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, replaySafeDigest);
        bytes memory signature = abi.encodePacked(r, s, v);
        return account.wrapSignature(0, signature);
    }

    function _encodePolicyData(uint256 topUp, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return _encodePolicyDataLocal(binding, policyConfig, topUp, nonce, deadline);
    }

    function _encodePolicyDataLocal(
        PolicyManager.PolicyBinding memory binding_,
        bytes memory policyConfig_,
        uint256 topUp,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes memory actionData = abi.encode(MorphoLoanProtectionPolicy.TopUpData({topUpAssets: topUp}));

        bytes32 digest = _hashTypedData(
            address(policy),
            "Morpho Loan Protection Policy",
            "1",
            keccak256(
                abi.encode(
                    policy.EXECUTION_TYPEHASH(),
                    policyManager.getPolicyId(binding_),
                    address(account),
                    keccak256(policyConfig_),
                    keccak256(abi.encode(keccak256(actionData), nonce, deadline))
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);

        return abi.encode(
            AOAPolicy.AOAExecutionData({nonce: nonce, deadline: deadline, signature: abi.encodePacked(r, s, v)}),
            actionData
        );
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

