// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "./PublicERC6492Validator.sol";
import {PolicyTypes} from "./PolicyTypes.sol";
import {Policy} from "./policies/Policy.sol";

/// @title PolicyManager
/// @notice Wallet-agnostic module that installs policies authorized by the account and executes policy-prepared
///         calldata on the account.
contract PolicyManager is EIP712, ReentrancyGuard {
    /// @notice Separated contract for validating signatures and executing ERC-6492 side effects.
    PublicERC6492Validator public immutable PUBLIC_ERC6492_VALIDATOR;

    /// @notice EIP-712 hash of PolicyBinding type.
    bytes32 public constant POLICY_BINDING_TYPEHASH = keccak256(
        "PolicyBinding(address account,address policy,bytes32 policyConfigHash,uint48 validAfter,uint48 validUntil,uint256 salt)"
    );

    /// @notice Policy was installed.
    event PolicyInstalled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy was revoked.
    event PolicyRevoked(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy execution occurred.
    event PolicyExecuted(bytes32 indexed policyId, address indexed account, address indexed policy);

    error InvalidSignature();
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error PolicyNotInstalled(bytes32 policyId);
    error PolicyAlreadyRevoked(bytes32 policyId);
    error PolicyAlreadyInstalled(bytes32 policyId);
    error BeforeValidAfter(uint48 currentTimestamp, uint48 validAfter);
    error AfterValidUntil(uint48 currentTimestamp, uint48 validUntil);
    error AccountCallFailed(address account, bytes returnData);
    error InvalidSender(address sender, address expected);

    struct PolicyRecord {
        bool installed;
        bool revoked;
        PolicyTypes.PolicyBinding binding;
    }

    mapping(bytes32 policyId => PolicyRecord) internal _policies;

    modifier requireSender(address sender) {
        _requireSender(sender);
        _;
    }

    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }

    constructor(PublicERC6492Validator publicERC6492Validator) {
        PUBLIC_ERC6492_VALIDATOR = publicERC6492Validator;
    }

    /// @notice Install a policy via a signature from the account.
    /// @dev Compatible with ERC-6492 signatures including side effects.
    function installPolicyWithSignature(
        PolicyTypes.PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata userSig
    ) external nonReentrant returns (bytes32 policyId) {
        (bytes32 id, PolicyRecord storage p, bool isNewInstall) = _install(binding, policyConfig);
        policyId = id;
        if (!isNewInstall) return policyId;

        bytes32 digest = _hashTypedData(policyId);
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(binding.account, digest, userSig)) {
            revert InvalidSignature();
        }

        p.installed = true;
        p.binding = binding;
        _onInstall(binding, policyId, policyConfig);
        emit PolicyInstalled(policyId, binding.account, binding.policy);
    }

    /// @notice Install a policy via a direct call from the account.
    function installPolicy(PolicyTypes.PolicyBinding calldata binding, bytes calldata policyConfig)
        external
        nonReentrant
        requireSender(binding.account)
        returns (bytes32 policyId)
    {
        (bytes32 id, PolicyRecord storage p, bool isNewInstall) = _install(binding, policyConfig);
        policyId = id;
        if (!isNewInstall) return policyId;

        p.installed = true;
        p.binding = binding;
        _onInstall(binding, policyId, policyConfig);
        emit PolicyInstalled(policyId, binding.account, binding.policy);
    }

    /// @notice Revoke a policy via a direct call from the account.
    function revokePolicy(bytes32 policyId) external nonReentrant returns (PolicyTypes.PolicyBinding memory binding) {
        PolicyRecord storage p = _policies[policyId];
        if (!p.installed) revert PolicyNotInstalled(policyId);
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);

        binding = p.binding;
        _requireSender(binding.account);

        p.revoked = true;
        Policy(binding.policy).onRevoke(binding, policyId);
        emit PolicyRevoked(policyId, binding.account, binding.policy);
    }

    /// @notice Execute an action for an installed policy instance.
    /// @dev `policyConfig` is an opaque policy-defined config blob (often the full preimage bytes; may be empty).
    ///      Policies MUST validate that any supplied config preimage matches what was authorized in the binding.
    function execute(bytes32 policyId, bytes calldata policyConfig, bytes calldata policyData) external nonReentrant {
        PolicyRecord storage p = _policies[policyId];
        _validateActivePolicy(p, policyId);

        PolicyTypes.PolicyBinding memory binding = p.binding;
        _checkInstallWindow(binding.validAfter, binding.validUntil);

        (bytes memory accountCallData, bytes memory postCallData) =
            Policy(binding.policy).onExecute(binding, policyConfig, policyData, msg.sender);
        _callAccount(binding.account, accountCallData);
        _postCallPolicy(binding.policy, postCallData);

        emit PolicyExecuted(policyId, binding.account, binding.policy);
    }

    function getPolicyBindingStructHash(PolicyTypes.PolicyBinding calldata binding) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                POLICY_BINDING_TYPEHASH,
                binding.account,
                binding.policy,
                binding.policyConfigHash,
                binding.validAfter,
                binding.validUntil,
                binding.salt
            )
        );
    }

    function _checkPolicyConfigHash(bytes32 expected, bytes calldata policyConfig) internal pure {
        bytes32 actual = keccak256(policyConfig);
        if (actual != expected) revert PolicyConfigHashMismatch(actual, expected);
    }

    function _checkInstallWindow(uint48 validAfter, uint48 validUntil) internal view {
        uint48 currentTimestamp = uint48(block.timestamp);
        if (validAfter != 0 && currentTimestamp < validAfter) revert BeforeValidAfter(currentTimestamp, validAfter);
        if (validUntil != 0 && currentTimestamp >= validUntil) revert AfterValidUntil(currentTimestamp, validUntil);
    }

    function _validateActivePolicy(bytes32 policyId) internal view {
        PolicyRecord storage p = _policies[policyId];
        _validateActivePolicy(p, policyId);
    }

    function _validateActivePolicy(PolicyRecord storage p, bytes32 policyId) internal view {
        if (!p.installed) revert PolicyNotInstalled(policyId);
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);
    }

    function _install(PolicyTypes.PolicyBinding calldata binding, bytes calldata policyConfig)
        internal
        view
        returns (bytes32 policyId, PolicyRecord storage p, bool isNewInstall)
    {
        policyId = getPolicyBindingStructHash(binding);
        p = _policies[policyId];
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);

        if (p.installed) {
            return (policyId, p, false);
        }

        _checkPolicyConfigHash(binding.policyConfigHash, policyConfig);
        _checkInstallWindow(binding.validAfter, binding.validUntil);
        return (policyId, p, true);
    }

    function _callAccount(address account, bytes memory accountCallData) internal {
        (bool success, bytes memory returnData) = account.call(accountCallData);
        if (!success) revert AccountCallFailed(account, returnData);
    }

    function _onInstall(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId, bytes calldata policyConfig)
        internal
    {
        Policy(binding.policy).onInstall(binding, policyId, policyConfig);
    }

    function _postCallPolicy(address policy, bytes memory postCallData) internal {
        if (postCallData.length == 0) return;
        (bool success, bytes memory returnData) = policy.call(postCallData);
        if (!success) revert AccountCallFailed(policy, returnData);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Policy Manager";
        version = "1";
    }
}

