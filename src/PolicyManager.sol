// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "./PublicERC6492Validator.sol";
import {Policy} from "./policies/Policy.sol";

/// @title PolicyManager
/// @notice Wallet-agnostic module that installs policies authorized by the account and executes policy-prepared
///         calldata on the account.
contract PolicyManager is EIP712, ReentrancyGuard {
    /// @notice Separated contract for validating signatures and executing ERC-6492 side effects.
    PublicERC6492Validator public immutable PUBLIC_ERC6492_VALIDATOR;

    /// @notice EIP-712 hash of PolicyBinding type.
    bytes32 public constant POLICY_BINDING_TYPEHASH = keccak256(
        "PolicyBinding(address account,address policy,bytes32 policyConfigHash,uint40 validAfter,uint40 validUntil,uint256 salt)"
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
    error BeforeValidAfter(uint40 currentTimestamp, uint40 validAfter);
    error AfterValidUntil(uint40 currentTimestamp, uint40 validUntil);
    error ExternalCallFailed(address target, bytes returnData);
    error InvalidSender(address sender, address expected);

    /// @notice Policy binding parameters authorized by the account.
    struct PolicyBinding {
        address account;
        address policy;
        uint40 validAfter;
        uint40 validUntil;
        uint256 salt;
        bytes32 policyConfigHash;
    }

    // 1 slot
    struct PolicyRecord {
        bool installed;
        bool revoked;
        address account;
        uint40 validAfter;
        uint40 validUntil;
    }

    mapping(address policy => mapping(bytes32 policyId => PolicyRecord)) internal _policies;

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
        PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata userSig
    ) external nonReentrant returns (bytes32 policyId) {
        policyId = getPolicyBindingStructHash(binding);
        bytes32 digest = _hashTypedData(policyId);
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(binding.account, digest, userSig)) {
            revert InvalidSignature();
        }

        return _install(binding, policyConfig);
    }

    /// @notice Install a policy via a direct call from the account.
    function installPolicy(PolicyBinding calldata binding, bytes calldata policyConfig)
        external
        nonReentrant
        requireSender(binding.account)
        returns (bytes32 policyId)
    {
        return _install(binding, policyConfig);
    }

    /// @notice Revoke a policy via a direct call from the account.
    function revokePolicy(address policy, bytes32 policyId) external nonReentrant returns (bool revoked) {
        PolicyRecord storage p = _policies[policy][policyId];
        if (!p.installed) revert PolicyNotInstalled(policyId);
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);

        p.revoked = true;
        Policy(policy).onRevoke(policyId, p.account, msg.sender);
        emit PolicyRevoked(policyId, p.account, policy);
        return true;
    }

    /// @notice Execute an action for an installed policy instance.
    /// @dev `policyConfig` is an opaque policy-defined config blob (often the full preimage bytes; may be empty).
    ///      Policies MUST validate that any supplied config preimage matches what was authorized in the binding.
    function execute(address policy, bytes32 policyId, bytes calldata policyConfig, bytes calldata policyData)
        external
        nonReentrant
    {
        PolicyRecord storage p = _policies[policy][policyId];
        if (!p.installed) revert PolicyNotInstalled(policyId);
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);

        _checkInstallWindow(p.validAfter, p.validUntil);

        (bytes memory accountCallData, bytes memory postCallData) =
            Policy(policy).onExecute(policyId, p.account, policyConfig, policyData, msg.sender);
        _externalCall(p.account, accountCallData);
        _externalCall(policy, postCallData);

        emit PolicyExecuted(policyId, p.account, policy);
    }

    function getPolicyBindingStructHash(PolicyBinding calldata binding) public pure returns (bytes32) {
        return keccak256(abi.encode(POLICY_BINDING_TYPEHASH, binding));
    }

    function _install(PolicyBinding calldata binding, bytes calldata policyConfig) internal returns (bytes32 policyId) {
        policyId = getPolicyBindingStructHash(binding);
        PolicyRecord storage p = _policies[binding.policy][policyId];
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);

        if (p.installed) return policyId;

        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }
        _checkInstallWindow(binding.validAfter, binding.validUntil);

        p.installed = true;
        p.account = binding.account;
        p.validAfter = binding.validAfter;
        p.validUntil = binding.validUntil;
        Policy(binding.policy).onInstall(policyId, binding.account, policyConfig, msg.sender);
        emit PolicyInstalled(policyId, binding.account, binding.policy);

        return policyId;
    }

    function _externalCall(address target, bytes memory data) internal {
        if (data.length == 0) return;
        (bool success, bytes memory returnData) = target.call(data);
        if (!success) revert ExternalCallFailed(target, returnData);
    }

    function _checkInstallWindow(uint40 validAfter, uint40 validUntil) internal view {
        uint40 currentTimestamp = uint40(block.timestamp);
        if (validAfter != 0 && currentTimestamp < validAfter) revert BeforeValidAfter(currentTimestamp, validAfter);
        if (validUntil != 0 && currentTimestamp >= validUntil) revert AfterValidUntil(currentTimestamp, validUntil);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Policy Manager";
        version = "1";
    }
}
