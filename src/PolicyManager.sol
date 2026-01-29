// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {Address} from "openzeppelin-contracts/contracts/utils/Address.sol";
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

    /// @notice EIP-712 hash of InstallAndExecute type.
    /// @dev Binds an installation authorization to a specific policy execution (via `policyDataHash`).
    bytes32 public constant INSTALL_AND_EXECUTE_TYPEHASH =
        keccak256("InstallAndExecute(bytes32 policyId,bytes32 policyDataHash,uint256 deadline)");

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
    error InvalidInstallAndExecutePayload();
    error InstallAndExecuteExpired(uint256 currentTimestamp, uint256 deadline);
    error Unauthorized(address caller);
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

    /// @notice Payload used for install+execute in a single call.
    /// @dev Encoded as `abi.encode(binding, policyConfig, userSig, innerPolicyData, deadline)` and passed via
    ///      the `policyData` parameter of `execute` when the policy is not yet installed.
    struct InstallAndExecutePayload {
        PolicyBinding binding;
        bytes policyConfig;
        bytes userSig;
        bytes innerPolicyData;
        uint256 deadline;
    }

    // 1 slot
    struct PolicyRecord {
        bool installed;
        bool revoked;
        address account;
        uint40 validAfter;
        uint40 validUntil;
    }

    mapping(address policy => mapping(bytes32 policyId => PolicyRecord)) internal _policies; // TODO: make this public? or consider a getter for certain things. like pass config, get policy id, whether installed, etc.

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
        if (p.revoked) revert PolicyAlreadyRevoked(policyId);
        p.revoked = true;
        try Policy(policy).onRevoke(policyId, p.account, msg.sender) {}
        catch {
            if (msg.sender != p.account) revert Unauthorized(msg.sender);
        }
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
        _execute(policy, policyId, p.account, policyConfig, policyData, msg.sender);
    }

    /// @notice Install (with execution-bound authorization) and immediately execute in a single transaction.
    /// @dev This is a typed helper to avoid requiring integrators to deploy a batching contract.
    function executeWithInstall(InstallAndExecutePayload calldata payload) external nonReentrant {
        bytes32 policyId = getPolicyBindingStructHash(payload.binding);
        address policy = payload.binding.policy;
        if (policy == address(0)) revert InvalidInstallAndExecutePayload();

        PolicyRecord storage p = _policies[policy][policyId];
        // Idempotent behavior: if already installed, skip installation authorization and execute directly.
        // This avoids brittleness when multiple parties race to "be first" to install.
        if (p.installed) {
            if (p.revoked) revert PolicyAlreadyRevoked(policyId);
            _checkInstallWindow(p.validAfter, p.validUntil);
            _execute(policy, policyId, p.account, payload.policyConfig, payload.innerPolicyData, msg.sender);
            return;
        }

        // Verify an execution-bound install signature (cannot be replayed as a plain install).
        if (payload.deadline != 0 && block.timestamp > payload.deadline) {
            revert InstallAndExecuteExpired(block.timestamp, payload.deadline);
        }
        bytes32 digest = _hashTypedData(
            keccak256(
                abi.encode(INSTALL_AND_EXECUTE_TYPEHASH, policyId, keccak256(payload.innerPolicyData), payload.deadline)
            )
        );
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(
                payload.binding.account, digest, payload.userSig
            )) {
            revert InvalidSignature();
        }

        // Install policy instance and use the installed config/data for execution.
        _install(payload.binding, payload.policyConfig);
        PolicyRecord storage policyRecord = _policies[policy][policyId];
        if (policyRecord.revoked) revert PolicyAlreadyRevoked(policyId);
        _checkInstallWindow(policyRecord.validAfter, policyRecord.validUntil);

        _execute(policy, policyId, policyRecord.account, payload.policyConfig, payload.innerPolicyData, msg.sender);
    }

    function _execute(
        address policy,
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal {
        (bytes memory accountCallData, bytes memory postCallData) =
            Policy(policy).onExecute(policyId, account, policyConfig, policyData, caller);
        _externalCall(account, accountCallData);
        _externalCall(policy, postCallData);

        emit PolicyExecuted(policyId, account, policy);
    }

    function getAccountForPolicy(address policy, bytes32 policyId) external view returns (address account) {
        return _policies[policy][policyId].account;
    }

    /// @notice Convenience alias: compute the `policyId` for a binding.
    function getPolicyId(PolicyBinding calldata binding) external pure returns (bytes32 policyId) {
        return getPolicyBindingStructHash(binding);
    }

    /// @notice Return raw policy record fields for a policy instance.
    function getPolicyRecord(address policy, bytes32 policyId)
        external
        view
        returns (bool installed, bool revoked, address account, uint40 validAfter, uint40 validUntil)
    {
        PolicyRecord storage p = _policies[policy][policyId];
        return (p.installed, p.revoked, p.account, p.validAfter, p.validUntil);
    }

    /// @notice True if the policy is installed (even if revoked).
    function isPolicyInstalled(address policy, bytes32 policyId) external view returns (bool) {
        return _policies[policy][policyId].installed;
    }

    /// @notice True if the policy has been revoked.
    function isPolicyRevoked(address policy, bytes32 policyId) external view returns (bool) {
        return _policies[policy][policyId].revoked;
    }

    /// @notice True if the policy is installed and not revoked.
    function isPolicyActive(address policy, bytes32 policyId) external view returns (bool) {
        PolicyRecord storage p = _policies[policy][policyId];
        return p.installed && !p.revoked;
    }

    /// @notice True if the policy is installed, not revoked, and currently within its valid install window.
    function isPolicyActiveNow(address policy, bytes32 policyId) external view returns (bool) {
        PolicyRecord storage p = _policies[policy][policyId];
        if (!p.installed || p.revoked) return false;
        uint40 ts = uint40(block.timestamp);
        if (p.validAfter != 0 && ts < p.validAfter) return false;
        if (p.validUntil != 0 && ts >= p.validUntil) return false;
        return true;
    }

    function getPolicyBindingStructHash(PolicyBinding calldata binding) public pure returns (bytes32) {
        // Must match POLICY_BINDING_TYPEHASH field order (EIP-712 struct hashing).
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

    function _install(PolicyBinding calldata binding, bytes calldata policyConfig) internal returns (bytes32 policyId) {
        policyId = getPolicyBindingStructHash(binding);
        PolicyRecord storage policyRecord = _policies[binding.policy][policyId];
        if (policyRecord.revoked) revert PolicyAlreadyRevoked(policyId);

        // Idempotent behavior: installing an already-installed policy instance is a no-op.
        // - Do not call the policy hook (prevents signature replay from triggering policy-side effects).
        // - Do not emit an event (prevents indexer noise; callers can treat this as success).
        if (policyRecord.installed) return policyId;

        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }
        _checkInstallWindow(binding.validAfter, binding.validUntil);

        policyRecord.installed = true;
        policyRecord.account = binding.account;
        policyRecord.validAfter = binding.validAfter;
        policyRecord.validUntil = binding.validUntil;
        Policy(binding.policy).onInstall(policyId, binding.account, policyConfig, msg.sender);
        emit PolicyInstalled(policyId, binding.account, binding.policy);

        return policyId;
    }

    function _externalCall(address target, bytes memory data) internal {
        if (data.length == 0) return;
        Address.functionCall(target, data);
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
