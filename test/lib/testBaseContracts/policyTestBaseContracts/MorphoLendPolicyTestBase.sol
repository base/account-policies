// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

import {PublicERC6492Validator} from "../../../../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MorphoLendPolicy} from "../../../../src/policies/MorphoLendPolicy.sol";

import {MockCoinbaseSmartWallet} from "../../mocks/MockCoinbaseSmartWallet.sol";
import {MockMorphoVault} from "../../mocks/MockMorpho.sol";

contract MintableToken is ERC20 {
    constructor(string memory name_, string memory symbol_) ERC20(name_, symbol_) {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @title MorphoLendPolicyTestBase
///
/// @notice Shared fixture + helpers for `MorphoLendPolicy` unit tests.
abstract contract MorphoLendPolicyTestBase is Test {
    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    bytes32 internal constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 executionDataHash)");

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

    function setUpMorphoLendBase(uint256 salt) internal {
        account = new MockCoinbaseSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new MorphoLendPolicy(address(policyManager), owner);

        vm.prank(owner);
        account.addOwnerAddress(address(policyManager));

        loanToken = new MintableToken("Loan", "LOAN");
        vault = new MockMorphoVault(address(loanToken));

        bytes memory policySpecificConfig = abi.encode(
            MorphoLendPolicy.LendPolicyConfig({
                vault: address(vault),
                depositLimit: MorphoLendPolicy.DepositLimitConfig({allowance: uint160(1_000_000 ether), period: 1 days})
            })
        );
        policyConfig =
            abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), policySpecificConfig);

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

    function _decodePolicyConfig(bytes memory policyConfig_)
        internal
        pure
        returns (AOAPolicy.AOAConfig memory aoa, MorphoLendPolicy.LendPolicyConfig memory cfg)
    {
        bytes memory policySpecificConfig;
        (aoa, policySpecificConfig) = abi.decode(policyConfig_, (AOAPolicy.AOAConfig, bytes));
        cfg = abi.decode(policySpecificConfig, (MorphoLendPolicy.LendPolicyConfig));
    }

    function _encodePolicyConfig(AOAPolicy.AOAConfig memory aoa, MorphoLendPolicy.LendPolicyConfig memory cfg)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(aoa, abi.encode(cfg));
    }

    function _execWithNonce(uint256 assets, uint256 nonce) internal {
        MorphoLendPolicy.LendData memory ld = MorphoLendPolicy.LendData({depositAssets: assets});
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory policyData = _encodePolicyDataWithSig(binding, ld, nonce, 0);
        vm.prank(executor);
        policyManager.execute(address(policy), policyId, policyConfig, policyData);
    }

    function _encodePolicyDataWithSig(
        PolicyManager.PolicyBinding memory binding_,
        MorphoLendPolicy.LendData memory ld,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes memory actionData = abi.encode(ld);
        bytes32 execDigest = _getPolicyExecutionDigest(binding_, actionData, nonce, deadline);
        bytes memory sig = _signExecution(execDigest);

        return abi.encode(AOAPolicy.AOAExecutionData({nonce: nonce, deadline: deadline, signature: sig}), actionData);
    }

    function _signExecution(bytes32 execDigest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, execDigest);
        return abi.encodePacked(r, s, v);
    }

    function _getPolicyExecutionDigest(
        PolicyManager.PolicyBinding memory binding_,
        bytes memory actionData,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 policyId = policyManager.getPolicyId(binding_);
        bytes32 actionDataHash = keccak256(actionData);
        bytes32 executionDataHash = keccak256(abi.encode(actionDataHash, nonce, deadline));
        bytes32 structHash = keccak256(
            abi.encode(EXECUTION_TYPEHASH, policyId, binding_.account, binding_.policyConfigHash, executionDataHash)
        );
        return _hashTypedData(address(policy), "Morpho Lend Policy", "1", structHash);
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

