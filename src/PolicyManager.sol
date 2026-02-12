// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {Address} from "openzeppelin-contracts/contracts/utils/Address.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "./PublicERC6492Validator.sol";
import {Policy} from "./policies/Policy.sol";

/// @title PolicyManager
///
/// @notice Wallet-agnostic coordinator for installing policy instances (authorized by the account) and executing
///         policy-prepared calldata against the account as an owner.
///
/// @dev Trust boundary:
///      - Policies are untrusted and can revert in any hook.
///      - The manager enforces lifecycle invariants (installed/uninstalled, install window checks) and routes calls.
///      - Uninstallation includes an account escape hatch: if the effective caller is the account, uninstall cannot be
///        blocked by a reverting policy hook.
contract PolicyManager is EIP712, ReentrancyGuard {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy binding parameters authorized by the account.
    ///
    /// @dev The EIP-712 struct hash of this binding is the `policyId`.
    struct PolicyBinding {
        /// @dev Account that authorizes installation and is the target of policy executions.
        address account;
        /// @dev Policy contract implementing the hook interface.
        address policy;
        /// @dev Earliest timestamp (seconds) at which execution is allowed. Zero means “no lower bound”.
        uint40 validAfter;
        /// @dev Latest timestamp (seconds) after which execution is disallowed. Zero means “no upper bound”.
        uint40 validUntil;
        /// @dev User-supplied salt to allow multiple distinct bindings for the same (account, policy, configHash).
        uint256 salt;
        /// @dev Hash of the policy’s config preimage (opaque bytes interpreted by the policy).
        bytes32 policyConfigHash;
    }

    /// @notice Payload used for uninstall+install in a single call.
    struct ReplacePolicyPayload {
        /// @dev Old policy contract address to uninstall.
        address oldPolicy;
        /// @dev Old policyId to uninstall.
        bytes32 oldPolicyId;
        /// @dev Optional config preimage forwarded to the old policy's uninstall hook.
        bytes oldPolicyConfig;
        /// @dev New binding to install (authorized by `userSig`).
        PolicyBinding newBinding;
        /// @dev New config preimage bytes whose hash must match `newBinding.policyConfigHash`.
        bytes newPolicyConfig;
        /// @dev ERC-6492-compatible signature by `newBinding.account` over a replacement typed digest:
        ///      `_hashTypedData(keccak256(abi.encode(REPLACE_POLICY_TYPEHASH, account, oldPolicy, oldPolicyId, newPolicyId, deadline)))`.
        ///
        ///      This signs the `ReplacePolicy` struct (typehash `REPLACE_POLICY_TYPEHASH`) and cannot be replayed as a
        ///      plain install because it commits to both the old and new policy ids.
        bytes userSig;
        /// @dev Optional timestamp (seconds). If non-zero, the signature is invalid after this deadline.
        uint256 deadline;
    }

    /// @notice Payload used for uninstalling a policyId or cancelling a pre-install intent.
    ///
    /// @dev This unifies two flows under a single entrypoint:
    /// - Installed lifecycle: address by `(policy, policyId)`; `policyConfig` MAY be empty for account uninstalls.
    /// - Pre-install uninstallation: address by full `binding` + `policyConfig` so the manager can compute `policyId` and
    ///   enforce that the provided config matches the binding commitment.
    ///
    /// Mode selection:
    /// - If `binding.policy != address(0)`, the manager uses binding-mode (pre-install uninstallation).
    /// - Otherwise it uses policyId-mode (uninstall by `(policy, policyId)`).
    struct UninstallPayload {
        /// @dev Binding used for pre-install cancellation. Unused in policyId-mode.
        PolicyBinding binding;
        /// @dev Policy contract address used in policyId-mode. Unused in binding-mode.
        address policy;
        /// @dev Policy identifier used in policyId-mode. Unused in binding-mode.
        bytes32 policyId;
        /// @dev Policy-defined config bytes (often the config preimage). Required for binding-mode. Optional for policyId-mode.
        bytes policyConfig;
        /// @dev Optional policy-defined authorization payload forwarded to policy hooks.
        bytes uninstallData;
    }

    /// @notice Lifecycle record stored per (policy, policyId).
    struct PolicyRecord {
        /// @dev True once installed (never unset).
        bool installed;
        /// @dev True once uninstalled/cancelled (never unset).
        bool uninstalled;
        /// @dev Account associated with the binding (cached from the binding at install/uninstall time).
        address account;
        /// @dev Cached install window lower bound from the binding.
        uint40 validAfter;
        /// @dev Cached install window upper bound from the binding.
        uint40 validUntil;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Separated contract for validating signatures and executing ERC-6492 side effects.
    PublicERC6492Validator public immutable PUBLIC_ERC6492_VALIDATOR;

    /// @notice EIP-712 hash of PolicyBinding type.
    bytes32 public constant POLICY_BINDING_TYPEHASH = keccak256(
        "PolicyBinding(address account,address policy,bytes32 policyConfigHash,uint40 validAfter,uint40 validUntil,uint256 salt)"
    );

    /// @notice EIP-712 hash of ReplacePolicy type.
    ///
    /// @dev Binds an uninstallation authorization to a specific new policy installation.
    bytes32 public constant REPLACE_POLICY_TYPEHASH = keccak256(
        "ReplacePolicy(address account,address oldPolicy,bytes32 oldPolicyId,bytes32 newPolicyId,uint256 deadline)"
    );

    /// @notice Lifecycle records keyed by policy contract and binding-derived policyId.
    mapping(address policy => mapping(bytes32 policyId => PolicyRecord)) internal _policies;

    ////////////////////////////////////////////////////////////////
    ///                         Events                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted when a policy instance is installed.
    ///
    /// @param policyId EIP-712 struct hash of the binding.
    /// @param account Account that authorized the binding.
    /// @param policy Policy contract address.
    event PolicyInstalled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Emitted when a policy instance is uninstalled.
    ///
    /// @param policyId EIP-712 struct hash of the binding.
    /// @param account Account associated with the binding.
    /// @param policy Policy contract address.
    event PolicyUninstalled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Emitted after a policy execution has been performed.
    ///
    /// @param policyId EIP-712 struct hash of the binding.
    /// @param account Account that was called by the policy's prepared calldata.
    /// @param policy Policy contract address.
    /// @param executionDataHash Hash of the `executionData` forwarded to the policy.
    event PolicyExecuted(
        bytes32 indexed policyId, address indexed account, address indexed policy, bytes32 executionDataHash
    );

    /// @notice Emitted when one policy instance is replaced atomically by another.
    ///
    /// @param oldPolicyId Old policyId that was uninstalled.
    /// @param newPolicyId New policyId that was installed.
    /// @param account Account that authorized the replacement.
    /// @param oldPolicy Old policy contract address.
    /// @param newPolicy New policy contract address.
    event PolicyReplaced(
        bytes32 indexed oldPolicyId,
        bytes32 indexed newPolicyId,
        address indexed account,
        address oldPolicy,
        address newPolicy
    );

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when an account signature fails validation.
    error InvalidSignature();

    /// @notice Thrown when a supplied policy config preimage does not hash to the binding's `policyConfigHash`.
    ///
    /// @param actual Hash of the supplied config bytes.
    /// @param expected Hash committed in the binding.
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    /// @notice Thrown when a policy instance is expected to be installed but is not.
    error PolicyNotInstalled(bytes32 policyId);

    /// @notice Thrown when attempting an action on an uninstalled or cancelled policyId.
    error PolicyIsDisabled(bytes32 policyId);

    /// @notice Thrown when attempting to install a policyId that is already installed.
    error PolicyAlreadyInstalled(bytes32 policyId);

    /// @notice Thrown when an EIP-712 signature is past its deadline.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param deadline Signature deadline in seconds.
    error DeadlineExpired(uint256 currentTimestamp, uint256 deadline);

    /// @notice Thrown when a payload is malformed or inconsistent.
    error InvalidPayload();

    /// @notice Thrown when a policy hook reverts and the effective caller is not authorized to force uninstall.
    ///
    /// @param caller Effective caller for the uninstall attempt.
    error Unauthorized(address caller);

    /// @notice Thrown when executing outside the binding's lower-bound install window.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param validAfter Lower bound in seconds.
    error BeforeValidAfter(uint40 currentTimestamp, uint40 validAfter);

    /// @notice Thrown when executing outside the binding's upper-bound install window.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param validUntil Upper bound in seconds.
    error AfterValidUntil(uint40 currentTimestamp, uint40 validUntil);

    /// @notice Thrown when a caller restriction is violated.
    ///
    /// @param sender Actual sender.
    /// @param expected Expected sender.
    error InvalidSender(address sender, address expected);

    ////////////////////////////////////////////////////////////////
    ///                        Modifiers                         ///
    ////////////////////////////////////////////////////////////////

    /// @notice Restricts the call to a specific sender.
    ///
    /// @param sender Expected `msg.sender`.
    modifier requireSender(address sender) {
        _requireSender(sender);
        _;
    }

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the manager with a signature validator.
    ///
    /// @param publicERC6492Validator ERC-6492 validator used for account signatures (and counterfactual side effects).
    constructor(PublicERC6492Validator publicERC6492Validator) {
        PUBLIC_ERC6492_VALIDATOR = publicERC6492Validator;
    }

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////
    /// @notice Installs a policy using an account signature over the binding, optionally followed by an execution.
    ///
    /// @dev The signature only authorizes the binding (not the execution). Any `executionData` provided is forwarded to
    ///      the policy's execute hook, which MUST enforce its own execution authorization semantics.
    ///
    /// @param binding Policy binding parameters authorized by the account.
    /// @param policyConfig Full config preimage bytes whose hash must match `binding.policyConfigHash`.
    /// @param userSig Account signature authorizing the binding.
    /// @param executionData Optional policy-defined per-execution payload. If empty, no execution is performed.
    ///
    /// @return policyId Deterministic policy identifier derived from the binding.
    function installWithSignature(
        PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata userSig,
        bytes calldata executionData
    ) external nonReentrant returns (bytes32 policyId) {
        return _installWithSignature(binding, policyConfig, userSig, executionData);
    }

    /// @notice Installs a policy via a direct call from the account.
    ///
    /// @dev Installation is idempotent: if the policyId is already installed, this is a no-op.
    ///
    /// @param binding Policy binding parameters.
    /// @param policyConfig Full config preimage bytes whose hash must match `binding.policyConfigHash`.
    ///
    /// @return policyId Deterministic policy identifier derived from the binding.
    function install(PolicyBinding calldata binding, bytes calldata policyConfig)
        external
        nonReentrant
        requireSender(binding.account)
        returns (bytes32 policyId)
    {
        return _install(binding, policyConfig);
    }

    /// @notice Execute an action for an installed policy instance.
    ///
    /// @dev `policyConfig` is an opaque policy-defined config blob (often the full config preimage bytes; may be empty).
    ///      Policies MUST validate that any supplied config preimage matches what was authorized in the binding.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier for the binding.
    /// @param policyConfig Policy-defined config bytes (often the config preimage).
    /// @param executionData Policy-defined per-execution payload.
    function execute(address policy, bytes32 policyId, bytes calldata policyConfig, bytes calldata executionData)
        external
        nonReentrant
    {
        PolicyRecord storage policyRecord = _policies[policy][policyId];
        if (!policyRecord.installed) revert PolicyNotInstalled(policyId);
        if (policyRecord.uninstalled) revert PolicyIsDisabled(policyId);

        _checkValidityWindow(policyRecord.validAfter, policyRecord.validUntil);
        _execute(policy, policyId, policyRecord.account, policyConfig, executionData, msg.sender);
    }

    /// @notice Atomically uninstall an existing policy instance and install a new one (authorized by account signature).
    ///
    /// @dev Uses a dedicated EIP-712 typed message so the signature cannot be replayed as a plain install.
    ///
    /// @param payload Replace payload containing the old policy instance to uninstall and the new binding to install.
    ///
    /// @return newPolicyId Deterministic policy identifier for the new binding.
    function replace(ReplacePolicyPayload calldata payload) external nonReentrant returns (bytes32 newPolicyId) {
        if (payload.oldPolicy == address(0) || payload.newBinding.policy == address(0)) {
            revert InvalidPayload();
        }

        newPolicyId = getPolicyBindingStructHash(payload.newBinding);
        if (newPolicyId == payload.oldPolicyId) revert InvalidPayload();

        PolicyRecord storage oldRecord = _policies[payload.oldPolicy][payload.oldPolicyId];
        PolicyRecord storage newRecord = _policies[payload.newBinding.policy][newPolicyId];

        // Idempotent behavior: if the desired end state is already reached, return early.
        // This enables safe retries even after deadlines expire.
        if (
            oldRecord.uninstalled && newRecord.installed && !newRecord.uninstalled
                && newRecord.account == payload.newBinding.account
        ) {
            return newPolicyId;
        }

        // Ensure the old policy is installed for this account.
        if (!oldRecord.installed) revert PolicyNotInstalled(payload.oldPolicyId);
        if (oldRecord.uninstalled) revert PolicyIsDisabled(payload.oldPolicyId);
        if (oldRecord.account != payload.newBinding.account) revert InvalidPayload();

        // Ensure the new policy instance is not already installed.
        if (newRecord.installed) revert PolicyAlreadyInstalled(newPolicyId);

        // Verify replacement signature.
        _requireNotExpired(payload.deadline);
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
        _requireValidAccountSig(payload.newBinding.account, digest, payload.userSig);

        // Uninstall old as-if called by the account (signature proves authorization).
        _uninstallForReplace(
            payload.oldPolicy,
            payload.oldPolicyId,
            payload.oldPolicyConfig,
            "",
            payload.newBinding.policy,
            newPolicyId,
            payload.newBinding.account
        );

        // Install new policy instance.
        _installForReplace(payload.newBinding, payload.newPolicyConfig, "", payload.oldPolicy, payload.oldPolicyId);

        emit PolicyReplaced(
            payload.oldPolicyId, newPolicyId, payload.newBinding.account, payload.oldPolicy, payload.newBinding.policy
        );
    }

    /// @notice Uninstall a policyId (installed lifecycle) or preemptively tombstone a policyId before installation.
    ///
    /// @dev Installed lifecycle (policyId-mode): address by `(policy, policyId)`.
    /// - `policyConfig` MAY be empty. If the effective caller is the account, the manager will still succeed even if the
    ///   policy hook reverts due to missing config (account escape hatch).
    ///
    /// Pre-install uninstallation (binding-mode): address by `(binding, policyConfig)` so the manager can compute `policyId`
    /// and enforce that the provided config matches `binding.policyConfigHash`.
    ///
    /// @param payload Uninstall payload selecting binding-mode or policyId-mode.
    ///
    /// @return policyId Policy identifier that was uninstalled/cancelled.
    function uninstall(UninstallPayload calldata payload) external nonReentrant returns (bytes32 policyId) {
        return _uninstall(payload, msg.sender);
    }

    ////////////////////////////////////////////////////////////////
    ///                 External View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Returns the account stored for a (policy, policyId).
    ///
    /// @dev Returns zero if the policyId has never been installed/cancelled.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier.
    ///
    /// @return account Account associated with the policyId.
    function getAccountForPolicy(address policy, bytes32 policyId) external view returns (address account) {
        return _policies[policy][policyId].account;
    }

    /// @notice Batch version of `getAccountForPolicy`.
    ///
    /// @param policy Policy contract address.
    /// @param policyIds Policy identifiers.
    ///
    /// @return accounts Accounts associated with each policyId (zero if never installed/cancelled).
    function getAccountsForPolicies(address policy, bytes32[] calldata policyIds)
        external
        view
        returns (address[] memory accounts)
    {
        uint256 len = policyIds.length;
        accounts = new address[](len);
        for (uint256 i; i < len; ++i) {
            accounts[i] = _policies[policy][policyIds[i]].account;
        }
    }

    /// @notice Return raw policy record fields for a policy instance.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier.
    ///
    /// @return installed True once installed (never unset).
    /// @return uninstalled True once uninstalled/cancelled (never unset).
    /// @return account Account associated with the policyId.
    /// @return validAfter Lower bound timestamp (seconds), or zero if unset.
    /// @return validUntil Upper bound timestamp (seconds), or zero if unset.
    function getPolicyRecord(address policy, bytes32 policyId)
        external
        view
        returns (bool installed, bool uninstalled, address account, uint40 validAfter, uint40 validUntil)
    {
        PolicyRecord storage policyRecord = _policies[policy][policyId];
        return (
            policyRecord.installed,
            policyRecord.uninstalled,
            policyRecord.account,
            policyRecord.validAfter,
            policyRecord.validUntil
        );
    }

    /// @notice Batch version of `getPolicyRecord`.
    ///
    /// @param policy Policy contract address.
    /// @param policyIds Policy identifiers.
    ///
    /// @return installed True once installed (never unset), per policyId.
    /// @return uninstalled True once uninstalled/cancelled (never unset), per policyId.
    /// @return account Account associated with each policyId.
    /// @return validAfter Lower bound timestamp (seconds), or zero if unset, per policyId.
    /// @return validUntil Upper bound timestamp (seconds), or zero if unset, per policyId.
    function getPolicyRecords(address policy, bytes32[] calldata policyIds)
        external
        view
        returns (
            bool[] memory installed,
            bool[] memory uninstalled,
            address[] memory account,
            uint40[] memory validAfter,
            uint40[] memory validUntil
        )
    {
        uint256 len = policyIds.length;
        installed = new bool[](len);
        uninstalled = new bool[](len);
        account = new address[](len);
        validAfter = new uint40[](len);
        validUntil = new uint40[](len);

        for (uint256 i; i < len; ++i) {
            PolicyRecord storage policyRecord = _policies[policy][policyIds[i]];
            installed[i] = policyRecord.installed;
            uninstalled[i] = policyRecord.uninstalled;
            account[i] = policyRecord.account;
            validAfter[i] = policyRecord.validAfter;
            validUntil[i] = policyRecord.validUntil;
        }
    }

    /// @notice True if the policy is installed (even if uninstalled).
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier.
    function isPolicyInstalled(address policy, bytes32 policyId) external view returns (bool) {
        return _policies[policy][policyId].installed;
    }

    /// @notice True if the policy has been uninstalled.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier.
    function isPolicyUninstalled(address policy, bytes32 policyId) external view returns (bool) {
        return _policies[policy][policyId].uninstalled;
    }

    /// @notice True if the policy is installed and not uninstalled.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier.
    function isPolicyActive(address policy, bytes32 policyId) external view returns (bool) {
        PolicyRecord storage policyRecord = _policies[policy][policyId];
        return policyRecord.installed && !policyRecord.uninstalled;
    }

    /// @notice True if the policy is installed, not uninstalled, and currently within its valid install window.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier.
    function isPolicyActiveNow(address policy, bytes32 policyId) external view returns (bool) {
        PolicyRecord storage policyRecord = _policies[policy][policyId];
        if (!policyRecord.installed || policyRecord.uninstalled) return false;
        uint40 currentTimestamp = uint40(block.timestamp);
        if (policyRecord.validAfter != 0 && currentTimestamp < policyRecord.validAfter) return false;
        if (policyRecord.validUntil != 0 && currentTimestamp >= policyRecord.validUntil) return false;
        return true;
    }

    ////////////////////////////////////////////////////////////////
    ///                 External Pure Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Convenience alias: compute the `policyId` for a binding.
    ///
    /// @param binding Policy binding parameters.
    ///
    /// @return policyId Deterministic policy identifier derived from the binding.
    function getPolicyId(PolicyBinding calldata binding) external pure returns (bytes32 policyId) {
        return getPolicyBindingStructHash(binding);
    }

    ////////////////////////////////////////////////////////////////
    ///                     Public Functions                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Computes the EIP-712 struct hash of a binding.
    ///
    /// @dev This value is used as the `policyId` throughout the system.
    ///
    /// @param binding Policy binding parameters.
    ///
    /// @return Hash of the EIP-712-encoded binding struct.
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

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Installs a policy instance after the caller has been authorized (directly or via signature).
    ///
    /// @dev Enforces config hash match and install window validity. Installation is idempotent.
    ///
    /// @param binding Policy binding parameters.
    /// @param policyConfig Full config preimage bytes whose hash must match `binding.policyConfigHash`.
    ///
    /// @return policyId Deterministic policy identifier derived from the binding.
    function _install(PolicyBinding calldata binding, bytes calldata policyConfig) internal returns (bytes32 policyId) {
        policyId = getPolicyBindingStructHash(binding);
        PolicyRecord storage policyRecord = _policies[binding.policy][policyId];
        if (policyRecord.uninstalled) revert PolicyIsDisabled(policyId);

        // Idempotent behavior: installing an already-installed policy instance is a no-op.
        if (policyRecord.installed) return policyId;

        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }
        _checkValidityWindow(binding.validAfter, binding.validUntil);

        policyRecord.installed = true;
        policyRecord.account = binding.account;
        policyRecord.validAfter = binding.validAfter;
        policyRecord.validUntil = binding.validUntil;
        Policy(binding.policy).onInstall(policyId, binding.account, policyConfig, msg.sender);
        emit PolicyInstalled(policyId, binding.account, binding.policy);

        return policyId;
    }

    function _installWithSignature(
        PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata userSig,
        bytes calldata executionData
    ) internal returns (bytes32 policyId) {
        policyId = getPolicyBindingStructHash(binding);
        bytes32 digest = _hashTypedData(policyId);
        _requireValidAccountSig(binding.account, digest, userSig);

        _install(binding, policyConfig);

        if (executionData.length == 0) return policyId;

        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }

        PolicyRecord storage policyRecord = _policies[binding.policy][policyId];
        if (policyRecord.uninstalled) revert PolicyIsDisabled(policyId);
        _checkValidityWindow(policyRecord.validAfter, policyRecord.validUntil);
        _execute(binding.policy, policyId, policyRecord.account, policyConfig, executionData, msg.sender);
        return policyId;
    }

    /// @notice Executes an action for a policy instance.
    ///
    /// @dev Calls the policy hook to obtain account calldata and optional post-call calldata, then:
    ///      1) calls the account
    ///      2) calls the policy (post-call)
    ///      This design allows policies to clean up approvals or internal state after the account call.
    ///
    /// @param policy Policy contract address.
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the binding.
    /// @param policyConfig Policy-defined config bytes (often the config preimage).
    /// @param executionData Policy-defined per-execution payload.
    /// @param caller Immediate external caller that invoked the manager.
    function _execute(
        address policy,
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal {
        (bytes memory accountCallData, bytes memory postCallData) =
            Policy(policy).onExecute(policyId, account, policyConfig, executionData, caller);
        _externalCall(account, accountCallData);
        _externalCall(policy, postCallData);

        emit PolicyExecuted(policyId, account, policy, keccak256(executionData));
    }

    function _uninstall(UninstallPayload calldata payload, address effectiveCaller)
        internal
        returns (bytes32 policyId)
    {
        // Binding-mode: supports pre-install cancellation and (optionally) uninstalling installed instances.
        if (payload.binding.policy != address(0)) {
            PolicyBinding calldata binding = payload.binding;
            policyId = getPolicyBindingStructHash(binding);
            PolicyRecord storage policyRecordByBinding = _policies[binding.policy][policyId];

            // Idempotent behavior: uninstalling an already-uninstalled policyId is a no-op.
            if (policyRecordByBinding.uninstalled) return policyId;

            // Installed lifecycle: uninstall by policyId. Config may be empty (account escape hatch).
            if (policyRecordByBinding.installed) {
                policyRecordByBinding.uninstalled = true;
                try Policy(binding.policy)
                    .onUninstall(
                        policyId,
                        policyRecordByBinding.account,
                        payload.policyConfig,
                        payload.uninstallData,
                        effectiveCaller
                    ) {}
                catch {
                    if (effectiveCaller != policyRecordByBinding.account) {
                        revert Unauthorized(effectiveCaller);
                    }
                }
                emit PolicyUninstalled(policyId, policyRecordByBinding.account, binding.policy);
                return policyId;
            }

            if (payload.policyConfig.length == 0) revert InvalidPayload();
            bytes32 actualConfigHash = keccak256(payload.policyConfig);
            if (actualConfigHash != binding.policyConfigHash) {
                revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
            }

            // Pre-install uninstallation: enforce policy-defined authorization.
            policyRecordByBinding.uninstalled = true;
            policyRecordByBinding.account = binding.account;
            policyRecordByBinding.validAfter = binding.validAfter;
            policyRecordByBinding.validUntil = binding.validUntil;

            try Policy(binding.policy)
                .onUninstall(policyId, binding.account, payload.policyConfig, payload.uninstallData, effectiveCaller) {}
            catch {
                if (effectiveCaller != binding.account) revert Unauthorized(effectiveCaller);
            }

            emit PolicyUninstalled(policyId, binding.account, binding.policy);
            return policyId;
        }

        // PolicyId-mode: uninstall by (policy, policyId).
        if (payload.policy == address(0) || payload.policyId == bytes32(0)) revert InvalidPayload();
        policyId = payload.policyId;
        PolicyRecord storage policyRecordById = _policies[payload.policy][policyId];
        // Idempotent behavior: uninstalling an already-uninstalled policyId is a no-op.
        if (policyRecordById.uninstalled) return policyId;
        if (!policyRecordById.installed) revert PolicyNotInstalled(policyId);
        policyRecordById.uninstalled = true;
        try Policy(payload.policy)
            .onUninstall(
                policyId, policyRecordById.account, payload.policyConfig, payload.uninstallData, effectiveCaller
            ) {}
        catch {
            if (effectiveCaller != policyRecordById.account) {
                revert Unauthorized(effectiveCaller);
            }
        }
        emit PolicyUninstalled(policyId, policyRecordById.account, payload.policy);
        return policyId;
    }

    /// @notice Uninstalls a policyId while invoking the replacement-aware policy hook.
    ///
    /// @dev Mirrors `_uninstall` semantics (including the account escape hatch) but calls `Policy.onReplace` with
    ///      `role == OldPolicy` so the policy can distinguish replacement from a standalone uninstallation.
    ///
    /// @param policy Policy contract address being uninstalled.
    /// @param policyId Policy identifier for the old binding.
    /// @param policyConfig Policy-defined config bytes (often the config preimage).
    /// @param replaceData Optional policy-defined replacement payload forwarded to `onReplace`.
    /// @param otherPolicy New policy contract address being installed.
    /// @param otherPolicyId Policy identifier for the new binding.
    /// @param effectiveCaller Effective caller forwarded by the manager (used for authorization + escape hatch).
    function _uninstallForReplace(
        address policy,
        bytes32 policyId,
        bytes memory policyConfig,
        bytes memory replaceData,
        address otherPolicy,
        bytes32 otherPolicyId,
        address effectiveCaller
    ) internal {
        PolicyRecord storage policyRecord = _policies[policy][policyId];
        // Idempotent behavior: uninstalling an already-uninstalled policyId is a no-op.
        if (policyRecord.uninstalled) return;
        if (!policyRecord.installed) revert PolicyNotInstalled(policyId);
        policyRecord.uninstalled = true;
        try Policy(policy)
            .onReplace(
                policyId,
                policyRecord.account,
                policyConfig,
                replaceData,
                otherPolicy,
                otherPolicyId,
                Policy.ReplaceRole.OldPolicy,
                effectiveCaller
            ) {}
        catch {
            if (effectiveCaller != policyRecord.account) revert Unauthorized(effectiveCaller);
        }
        emit PolicyUninstalled(policyId, policyRecord.account, policy);
    }

    /// @notice Installs a policy instance while invoking the replacement-aware policy hook.
    ///
    /// @dev Mirrors `_install` semantics but calls `Policy.onReplace` with `role == NewPolicy` so the policy can
    ///      distinguish replacement from a standalone installation.
    ///
    /// @param binding New binding to install.
    /// @param policyConfig Full config preimage bytes whose hash must match `binding.policyConfigHash`.
    /// @param replaceData Optional policy-defined replacement payload forwarded to `onReplace`.
    /// @param otherPolicy Old policy contract address being uninstalled.
    /// @param otherPolicyId Policy identifier for the old binding.
    ///
    /// @return policyId Deterministic policy identifier derived from the binding.
    function _installForReplace(
        PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes memory replaceData,
        address otherPolicy,
        bytes32 otherPolicyId
    ) internal returns (bytes32 policyId) {
        policyId = getPolicyBindingStructHash(binding);
        PolicyRecord storage policyRecord = _policies[binding.policy][policyId];
        if (policyRecord.uninstalled) revert PolicyIsDisabled(policyId);

        // Idempotent behavior: installing an already-installed policy instance is a no-op.
        if (policyRecord.installed) return policyId;

        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }
        _checkValidityWindow(binding.validAfter, binding.validUntil);

        policyRecord.installed = true;
        policyRecord.account = binding.account;
        policyRecord.validAfter = binding.validAfter;
        policyRecord.validUntil = binding.validUntil;

        Policy(binding.policy)
            .onReplace(
                policyId,
                binding.account,
                policyConfig,
                replaceData,
                otherPolicy,
                otherPolicyId,
                Policy.ReplaceRole.NewPolicy,
                msg.sender
            );
        emit PolicyInstalled(policyId, binding.account, binding.policy);

        return policyId;
    }

    /// @notice Requires `msg.sender` to equal `sender`.
    ///
    /// @param sender Expected sender.
    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }

    /// @notice Performs an external call if `data` is non-empty.
    ///
    /// @dev Uses `Address.functionCall` to bubble revert reasons.
    ///
    /// @param target Call target.
    /// @param data ABI-encoded calldata.
    function _externalCall(address target, bytes memory data) internal {
        if (data.length == 0) return;
        Address.functionCall(target, data);
    }

    /// @dev Reverts if `deadline` is non-zero and already expired.
    function _requireNotExpired(uint256 deadline) internal view {
        if (deadline != 0 && block.timestamp > deadline) revert DeadlineExpired(block.timestamp, deadline);
    }

    /// @dev Requires `account` to have signed `digest` (ERC-6492 supported, side effects allowed).
    function _requireValidAccountSig(address account, bytes32 digest, bytes calldata signature) internal {
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(account, digest, signature)) {
            revert InvalidSignature();
        }
    }

    /// @notice Reverts if the current timestamp is outside the validity window.
    ///
    /// @param validAfter Lower bound timestamp (seconds), or zero if unset.
    /// @param validUntil Upper bound timestamp (seconds), or zero if unset.
    function _checkValidityWindow(uint40 validAfter, uint40 validUntil) internal view {
        uint40 currentTimestamp = uint40(block.timestamp);
        if (validAfter != 0 && currentTimestamp < validAfter) revert BeforeValidAfter(currentTimestamp, validAfter);
        if (validUntil != 0 && currentTimestamp >= validUntil) revert AfterValidUntil(currentTimestamp, validUntil);
    }

    /// @dev EIP-712 domain metadata.
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Policy Manager";
        version = "1";
    }
}
