// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PolicyManager} from "../PolicyManager.sol";

import {Policy} from "./Policy.sol";

/// @title SingleExecutorPolicy
///
/// @notice Abstract base for policies that rely on a single executor address for authorization.
///
/// @dev This base contract owns the canonical ABI encoding shapes and shared infrastructure:
///      - `policyConfig = abi.encode(SingleExecutorConfig{executor}, bytes policySpecificConfig)`
///      - `executionData = abi.encode(SingleExecutorExecutionData{nonce, deadline, signature}, bytes actionData)`
///
///      Subclasses implement the template-method hooks to define how the executor is used
///      (e.g., always-required signature vs. optional/delegated).
abstract contract SingleExecutorPolicy is Policy, AccessControl, Pausable, EIP712 {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Shared config prefix for single-executor policies.
    struct SingleExecutorConfig {
        /// @dev Executor authorized to execute and uninstall (directly or via signature).
        address executor;
    }

    /// @notice Execution envelope for single-executor policies.
    struct SingleExecutorExecutionData {
        /// @dev Policy-defined execution nonce used for replay protection.
        uint256 nonce;
        /// @dev Optional signature expiry timestamp (seconds). Zero means "no expiry".
        uint256 deadline;
        /// @dev Executor signature authorizing this execution intent.
        bytes signature;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Role identifier for addresses authorized to pause/unpause the policy.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Stored config hash per policy instance.
    ///
    /// @dev Single-executor policies are calldata-heavy; they store only a hash and require the full config preimage
    ///      for execution.
    mapping(bytes32 policyId => bytes32 configHash) internal _configHashByPolicyId;

    /// @notice Tracks used nonces per policyId to prevent replay of executor-signed executions.
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    /// @notice EIP-712 typehash for executor-signed execution intents.
    ///
    /// @dev Outer signed struct tying an execution to a policy instance.
    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execution(bytes32 policyId,address account,bytes32 policyConfigHash,ExecutionData executionData)"
        "ExecutionData(bytes actionData,uint256 nonce,uint256 deadline)"
    );

    /// @notice EIP-712 typehash for the inner execution data struct hashed inside `EXECUTION_TYPEHASH`.
    bytes32 public constant EXECUTION_DATA_TYPEHASH =
        keccak256("ExecutionData(bytes actionData,uint256 nonce,uint256 deadline)");

    /// @notice EIP-712 typehash for executor-signed uninstall intents.
    bytes32 public constant SINGLE_EXECUTOR_UNINSTALL_TYPEHASH = keccak256(
        "SingleExecutorUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)"
    );

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when a supplied config preimage hash does not match the stored hash for the policyId.
    ///
    /// @param actual Hash of the supplied config bytes.
    /// @param expected Stored hash committed at install time.
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    /// @notice Thrown when the decoded executor address is zero.
    error ZeroExecutor();

    /// @notice Thrown when the configured admin is zero.
    error ZeroAdmin();

    /// @notice Thrown when a non-account caller fails executor authorization.
    ///
    /// @param caller External caller.
    error Unauthorized(address caller);

    /// @notice Thrown when an executor-signed intent is past its deadline.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param deadline Signature deadline in seconds.
    error SignatureExpired(uint256 currentTimestamp, uint256 deadline);

    /// @notice Thrown when a nonce has already been used for this policyId.
    ///
    /// @param policyId Policy identifier.
    /// @param nonce Execution nonce.
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);

    /// @notice Thrown when the caller is not the executor for the given policy.
    ///
    /// @param caller The unauthorized caller.
    /// @param executor Expected executor address.
    error UnauthorizedCanceller(address caller, address executor);

    ////////////////////////////////////////////////////////////////
    ///                         Events                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted when the authorized PolicyManager is updated.
    ///
    /// @param oldManager The previous PolicyManager address.
    /// @param newManager The new PolicyManager address.
    event PolicyManagerUpdated(address oldManager, address newManager);

    /// @notice Emitted when a nonce is explicitly cancelled.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param nonce The cancelled nonce.
    /// @param canceller The address that cancelled the nonce (executor or account).
    event NonceCancelled(bytes32 indexed policyId, uint256 nonce, address canceller);

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy and grants the admin and pauser roles.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` and `PAUSER_ROLE`.
    constructor(address policyManager, address admin) Policy(policyManager) {
        if (admin == address(0)) revert ZeroAdmin();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Updates the authorized PolicyManager address.
    ///
    /// @dev Only callable by `DEFAULT_ADMIN_ROLE`. Reverts if the new address has no deployed code.
    ///
    /// @param newPolicyManager Address of the new PolicyManager.
    function setPolicyManager(address newPolicyManager) external virtual onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newPolicyManager.code.length == 0) revert PolicyManagerNotContract(newPolicyManager);
        address oldManager = address(policyManager);
        policyManager = PolicyManager(newPolicyManager);
        emit PolicyManagerUpdated(oldManager, newPolicyManager);
    }

    /// @notice Pauses execution for this policy.
    ///
    /// @dev Only callable by `PAUSER_ROLE`.
    function pause() external virtual onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses execution for this policy.
    ///
    /// @dev Only callable by `PAUSER_ROLE`.
    function unpause() external virtual onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Cancels one or more nonces, preventing future execution intents that use them.
    ///
    /// @dev Callable only by the configured executor. Requires the installed config preimage to authenticate the
    ///      caller (consistent with the calldata-heavy pattern). Already-used nonces are skipped silently for
    ///      idempotency; only freshly-cancelled nonces emit `NonceCancelled`.
    ///
    ///      Not gated by `whenNotPaused` — nonce cancellation is a safety/revocation mechanism that should always work.
    ///      Accounts that wish to revoke all executor authority should use `uninstall` instead.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param nonces Array of nonces to cancel.
    /// @param policyConfig Full config preimage bytes (hash must match the stored config hash for `policyId`).
    function cancelNonces(bytes32 policyId, uint256[] calldata nonces, bytes calldata policyConfig) external virtual {
        _requireConfigHash(policyId, policyConfig);
        (SingleExecutorConfig memory singleExecutorConfig,) = _decodeSingleExecutorConfig(policyConfig);

        if (msg.sender != singleExecutorConfig.executor) {
            revert UnauthorizedCanceller(msg.sender, singleExecutorConfig.executor);
        }

        for (uint256 i; i < nonces.length; ++i) {
            if (!_usedNonces[policyId][nonces[i]]) {
                _usedNonces[policyId][nonces[i]] = true;
                emit NonceCancelled(policyId, nonces[i], msg.sender);
            }
        }
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Stores the config hash for a newly installed policyId.
    ///
    /// @param policyId Policy identifier.
    /// @param policyConfig Full config preimage bytes.
    function _storeConfigHash(bytes32 policyId, bytes calldata policyConfig) internal {
        _configHashByPolicyId[policyId] = keccak256(policyConfig);
    }

    /// @dev Validate executor signature using the policy manager's validator (supports ERC-6492 side effects).
    function _isValidExecutorSig(address executor, bytes32 digest, bytes memory signature) internal returns (bool) {
        return policyManager.PUBLIC_ERC6492_VALIDATOR().isValidSignatureNowAllowSideEffects(executor, digest, signature);
    }

    /// @dev Reverts if `nonce` is already used for `policyId`, then marks it as used.
    function _consumeNonce(bytes32 policyId, uint256 nonce) internal {
        if (_usedNonces[policyId][nonce]) revert ExecutionNonceAlreadyUsed(policyId, nonce);
        _usedNonces[policyId][nonce] = true;
    }

    /// @notice Computes the EIP-712 digest for an executor-signed execution intent.
    ///
    /// @dev Uses the stored config hash for `policyId`.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param executionDataHash Hash of the policy-specific action payload being authorized.
    ///
    /// @return EIP-712 digest to be signed by the executor.
    function _getExecutionDigest(bytes32 policyId, address account, bytes32 executionDataHash)
        internal
        view
        returns (bytes32)
    {
        return _getExecutionDigest(policyId, account, _configHashByPolicyId[policyId], executionDataHash);
    }

    /// @notice Computes the EIP-712 digest for an executor-signed execution intent.
    ///
    /// @dev Overload that accepts `configHash` to avoid an extra SLOAD when already available.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param configHash Stored config hash for the policyId.
    /// @param executionDataHash Hash of the policy-specific action payload being authorized.
    ///
    /// @return EIP-712 digest to be signed by the executor.
    function _getExecutionDigest(bytes32 policyId, address account, bytes32 configHash, bytes32 executionDataHash)
        internal
        view
        returns (bytes32)
    {
        return
            _hashTypedData(keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, account, configHash, executionDataHash)));
    }

    /// @notice Requires the supplied config preimage to match the stored hash for the policyId.
    ///
    /// @param policyId Policy identifier.
    /// @param policyConfig Full config preimage bytes.
    function _requireConfigHash(bytes32 policyId, bytes calldata policyConfig) internal view {
        bytes32 expected = _configHashByPolicyId[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);
    }

    /// @notice Decodes the canonical single-executor config prefix and policy-specific config.
    ///
    /// @dev Does NOT revert on zero executor — zero-address validation is the responsibility of the subclass
    ///      (e.g., `SingleExecutorAuthorizedPolicy` requires a non-zero executor at install time, while
    ///      future subclasses such as `MoiraiDelegate` may permit address(0)).
    ///
    /// @param policyConfig Full config preimage bytes.
    ///
    /// @return singleExecutorConfig Decoded single-executor config prefix.
    /// @return policySpecificConfig Remaining policy-specific config bytes.
    function _decodeSingleExecutorConfig(bytes calldata policyConfig)
        internal
        pure
        returns (SingleExecutorConfig memory singleExecutorConfig, bytes memory policySpecificConfig)
    {
        (singleExecutorConfig, policySpecificConfig) = abi.decode(policyConfig, (SingleExecutorConfig, bytes));
    }

    /// @notice Computes the EIP-712 digest for an executor-signed uninstall intent.
    ///
    /// @dev Commits to the policy instance (`policyId`), its associated account, and the stored config hash so the
    ///      signature cannot be reused across policy instances/configurations.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param configHash Config hash for the policyId.
    /// @param deadline Optional signature expiry timestamp (seconds). Zero means "no expiry".
    ///
    /// @return EIP-712 digest to be signed by the executor.
    function _getUninstallDigest(bytes32 policyId, address account, bytes32 configHash, uint256 deadline)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedData(
            keccak256(abi.encode(SINGLE_EXECUTOR_UNINSTALL_TYPEHASH, policyId, account, configHash, deadline))
        );
    }

    /// @notice Computes the execution intent hash committed to by the executor signature.
    ///
    /// @dev Uses `keccak256(actionData)` so the hash is size-bounded even when `actionData` is large.
    ///
    /// @param actionData Policy-specific action payload bytes.
    /// @param nonce Execution nonce used for replay protection.
    /// @param deadline Optional signature expiry timestamp (seconds). Zero means "no expiry".
    ///
    /// @return executionDataHash Hash used as `executionDataHash` in `EXECUTION_TYPEHASH`.
    function _getExecutionDataHash(bytes memory actionData, uint256 nonce, uint256 deadline)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(EXECUTION_DATA_TYPEHASH, keccak256(actionData), nonce, deadline));
    }

    /// @notice Validates and consumes an executor-signed execution intent.
    ///
    /// @dev Reverts if the intent is expired, replayed (nonce already used), or not signed by the configured executor.
    ///      On success, marks the nonce as used for `policyId`.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param executor Executor address authorized in `SingleExecutorConfig`.
    /// @param singleExecutorExecutionData Execution envelope containing nonce, deadline, and signature.
    /// @param actionData Policy-specific action payload bytes.
    /// @param caller External caller that invoked the manager (used only for error reporting).
    function _validateAndConsumeExecutionIntent(
        bytes32 policyId,
        address account,
        address executor,
        SingleExecutorExecutionData memory singleExecutorExecutionData,
        bytes memory actionData,
        address caller
    ) internal {
        _consumeNonce(policyId, singleExecutorExecutionData.nonce);

        if (singleExecutorExecutionData.deadline != 0 && block.timestamp > singleExecutorExecutionData.deadline) {
            revert SignatureExpired(block.timestamp, singleExecutorExecutionData.deadline);
        }

        bytes32 digest = _getExecutionDigest(
            policyId,
            account,
            _configHashByPolicyId[policyId],
            _getExecutionDataHash(actionData, singleExecutorExecutionData.nonce, singleExecutorExecutionData.deadline)
        );

        if (!_isValidExecutorSig(executor, digest, singleExecutorExecutionData.signature)) {
            revert Unauthorized(caller);
        }
    }
}
