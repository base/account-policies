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

    /// @notice EIP-712 hash of ReplacePolicy type.
    /// @dev Binds an uninstallation authorization to a specific new policy installation.
    bytes32 public constant REPLACE_POLICY_TYPEHASH =
        keccak256("ReplacePolicy(address account,address oldPolicy,bytes32 oldPolicyId,bytes32 newPolicyId,uint256 deadline)");

    /// @notice Policy was installed.
    event PolicyInstalled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy was uninstalled.
    event PolicyUninstalled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy execution occurred.
    event PolicyExecuted(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy installation intent was cancelled before installation.
    event PolicyCancelled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy instance was replaced atomically.
    event PolicyReplaced(
        bytes32 indexed oldPolicyId,
        bytes32 indexed newPolicyId,
        address indexed account,
        address oldPolicy,
        address newPolicy
    );

    error InvalidSignature();
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error PolicyNotInstalled(bytes32 policyId);
    error PolicyIsUninstalled(bytes32 policyId);
    error PolicyAlreadyInstalled(bytes32 policyId);
    error ReplacePolicyExpired(uint256 currentTimestamp, uint256 deadline);
    error InvalidReplacePolicyPayload();
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

    /// @notice Payload used for uninstall+install in a single call.
    struct ReplacePolicyPayload {
        address oldPolicy;
        bytes32 oldPolicyId;
        bytes oldPolicyConfig; // optional; forwarded to the old policy's uninstall hook
        PolicyBinding newBinding;
        bytes newPolicyConfig;
        bytes userSig;
        uint256 deadline;
    }

    // 1 slot
    struct PolicyRecord {
        bool installed;
        bool uninstalled;
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

    /// @notice Cancel a policy installation intent (including preemptively, before installation).
    /// @dev This is distinct from uninstallation:
    /// - If the policy is already installed, this uninstalls it (calling the policy hook and emitting `PolicyUninstalled`).
    /// - If the policy is not installed, it marks the policyId as uninstalled to permanently block future installs and
    ///   emits `PolicyCancelled`.
    ///
    /// Authorization:
    /// - If installed: authorization is enforced by the policy's `onUninstall` hook.
    /// - If not installed: authorization is enforced by the policy's `onCancel` hook.
    ///
    /// To "uncancel", the account must sign/install a new binding with a new salt (i.e., a different `policyId`).
    function cancelPolicy(PolicyBinding calldata binding, bytes calldata policyConfig)
        external
        nonReentrant
        returns (bytes32 policyId)
    {
        if (binding.policy == address(0)) revert InvalidReplacePolicyPayload();
        policyId = getPolicyBindingStructHash(binding);
        PolicyRecord storage p = _policies[binding.policy][policyId];

        // Idempotent behavior: cancelling an already-uninstalled policyId is a no-op.
        if (p.uninstalled) return policyId;

        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }

        // If installed, uninstall normally (hook + event) using the caller.
        if (p.installed) {
            _uninstall(binding.policy, policyId, policyConfig);
            return policyId;
        }

        // Pre-install cancel: enforce policy-defined authorization.
        Policy(binding.policy).onCancel(policyId, binding.account, policyConfig, msg.sender);

        // Mark as uninstalled to permanently block future installs.
        p.uninstalled = true;
        p.account = binding.account;
        p.validAfter = binding.validAfter;
        p.validUntil = binding.validUntil;

        emit PolicyCancelled(policyId, binding.account, binding.policy);
        return policyId;
    }

    /// @notice Uninstall a policy, optionally providing `policyConfig`.
    /// @dev `policyConfig` MAY be empty. Policies can use it to authorize non-account uninstallers.
    function uninstallPolicy(address policy, bytes32 policyId, bytes calldata policyConfig)
        external
        nonReentrant
        returns (bool uninstalled)
    {
        return _uninstall(policy, policyId, policyConfig);
    }

    function _uninstall(address policy, bytes32 policyId, bytes memory policyConfig) internal returns (bool uninstalled) {
        PolicyRecord storage p = _policies[policy][policyId];
        if (p.uninstalled) revert PolicyIsUninstalled(policyId);
        if (!p.installed) revert PolicyNotInstalled(policyId);
        p.uninstalled = true;
        try Policy(policy).onUninstall(policyId, p.account, policyConfig, msg.sender) {}
        catch {
            if (msg.sender != p.account) revert Unauthorized(msg.sender);
        }
        emit PolicyUninstalled(policyId, p.account, policy);
        return true;
    }

    /// @notice Atomically uninstall an existing policy instance and install a new one (authorized by account signature).
    /// @dev Uses a dedicated EIP-712 typed message so the signature cannot be replayed as a plain install.
    function replacePolicyWithSignature(ReplacePolicyPayload calldata payload)
        external
        nonReentrant
        returns (bytes32 newPolicyId)
    {
        if (payload.oldPolicy == address(0) || payload.newBinding.policy == address(0)) {
            revert InvalidReplacePolicyPayload();
        }

        newPolicyId = getPolicyBindingStructHash(payload.newBinding);
        if (newPolicyId == payload.oldPolicyId) revert InvalidReplacePolicyPayload();

        // Ensure the old policy is installed for this account.
        PolicyRecord storage oldRecord = _policies[payload.oldPolicy][payload.oldPolicyId];
        if (!oldRecord.installed) revert PolicyNotInstalled(payload.oldPolicyId);
        if (oldRecord.uninstalled) revert PolicyIsUninstalled(payload.oldPolicyId);
        if (oldRecord.account != payload.newBinding.account) revert InvalidReplacePolicyPayload();

        // Ensure the new policy instance is not already installed.
        PolicyRecord storage newRecord = _policies[payload.newBinding.policy][newPolicyId];
        if (newRecord.installed) revert PolicyAlreadyInstalled(newPolicyId);

        // Verify replacement signature.
        if (payload.deadline != 0 && block.timestamp > payload.deadline) {
            revert ReplacePolicyExpired(block.timestamp, payload.deadline);
        }
        bytes32 digest = _hashTypedData(
            keccak256(
                abi.encode(
                    REPLACE_POLICY_TYPEHASH,
                    payload.newBinding.account,
                    payload.oldPolicy,
                    payload.oldPolicyId,
                    newPolicyId,
                    payload.deadline
                )
            )
        );
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(payload.newBinding.account, digest, payload.userSig))
        {
            revert InvalidSignature();
        }

        // Uninstall old as-if called by the account (signature proves authorization).
        _uninstallAs(payload.oldPolicy, payload.oldPolicyId, payload.oldPolicyConfig, payload.newBinding.account);

        // Install new policy instance.
        _install(payload.newBinding, payload.newPolicyConfig);

        emit PolicyReplaced(payload.oldPolicyId, newPolicyId, payload.newBinding.account, payload.oldPolicy, payload.newBinding.policy);
    }

    function _uninstallAs(address policy, bytes32 policyId, bytes calldata policyConfig, address caller) internal {
        PolicyRecord storage p = _policies[policy][policyId];
        if (p.uninstalled) revert PolicyIsUninstalled(policyId);
        if (!p.installed) revert PolicyNotInstalled(policyId);

        p.uninstalled = true;
        Policy(policy).onUninstall(policyId, p.account, policyConfig, caller);
        emit PolicyUninstalled(policyId, p.account, policy);
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
        if (p.uninstalled) revert PolicyIsUninstalled(policyId);

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
            if (p.uninstalled) revert PolicyIsUninstalled(policyId);
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
        if (policyRecord.uninstalled) revert PolicyIsUninstalled(policyId);
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
        returns (bool installed, bool uninstalled, address account, uint40 validAfter, uint40 validUntil)
    {
        PolicyRecord storage p = _policies[policy][policyId];
        return (p.installed, p.uninstalled, p.account, p.validAfter, p.validUntil);
    }

    /// @notice True if the policy is installed (even if uninstalled).
    function isPolicyInstalled(address policy, bytes32 policyId) external view returns (bool) {
        return _policies[policy][policyId].installed;
    }

    /// @notice True if the policy has been uninstalled.
    function isPolicyUninstalled(address policy, bytes32 policyId) external view returns (bool) {
        return _policies[policy][policyId].uninstalled;
    }

    /// @notice True if the policy is installed and not uninstalled.
    function isPolicyActive(address policy, bytes32 policyId) external view returns (bool) {
        PolicyRecord storage p = _policies[policy][policyId];
        return p.installed && !p.uninstalled;
    }

    /// @notice True if the policy is installed, not uninstalled, and currently within its valid install window.
    function isPolicyActiveNow(address policy, bytes32 policyId) external view returns (bool) {
        PolicyRecord storage p = _policies[policy][policyId];
        if (!p.installed || p.uninstalled) return false;
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
        if (policyRecord.uninstalled) revert PolicyIsUninstalled(policyId);

        // Idempotent behavior: installing an already-installed policy instance is a no-op.
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
