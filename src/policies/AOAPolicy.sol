// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {Policy} from "./Policy.sol";

/// @title AOAPolicy
///
/// @notice Template-method base for "Automated Onchain Actions" (AOA) policies.
///
/// @dev This base contract enforces canonical ABI encoding shapes by owning the internal hook implementations:
///      - `policyConfig = abi.encode(AOAConfig{account, executor}, bytes policySpecificConfig)`
///      - `executionData = abi.encode(AOAExecutionData{nonce, deadline, signature}, bytes actionData)`
///
///      The base layer also standardizes executor authorization:
///      - all executions require an executor signature (ERC-6492 supported)
abstract contract AOAPolicy is Policy, AccessControl, Pausable, EIP712 {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Shared config prefix for AOA policies.
    struct AOAConfig {
        /// @dev Account that installs the policy and is the target of policy executions.
        address account;
        /// @dev Executor authorized to execute/cancel/uninstall (directly or via signature).
        address executor;
    }

    struct AOAExecutionData {
        /// @dev Policy-defined execution nonce used for replay protection.
        uint256 nonce;
        /// @dev Optional signature expiry timestamp (seconds). Zero means “no expiry”.
        uint256 deadline;
        /// @dev Executor signature authorizing this execution intent.
        bytes signature;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Stored config hash per policy instance.
    ///
    /// @dev AOA policies are calldata-heavy; they store only a hash and require the full config preimage for execution.
    mapping(bytes32 policyId => bytes32 configHash) internal _configHashByPolicyId;

    /// @notice Tracks used nonces per policyId to prevent replay of executor-signed executions.
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    /// @notice EIP-712 typehash for executor-signed execution intents.
    ///
    /// @dev Outer signed struct tying an execution to a policy instance.
    bytes32 public constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 executionDataHash)");

    /// @notice EIP-712 typehash for executor-signed uninstall intents.
    bytes32 public constant AOA_UNINSTALL_TYPEHASH =
        keccak256("AOAUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)");

    /// @notice EIP-712 typehash for executor-signed cancel intents.
    bytes32 public constant AOA_CANCEL_TYPEHASH =
        keccak256("AOACancel(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)");

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when a supplied config preimage hash does not match the stored hash for the policyId.
    ///
    /// @param actual Hash of the supplied config bytes.
    /// @param expected Stored hash committed at install time.
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    /// @notice Thrown when the decoded AOA config's account does not match the expected account.
    ///
    /// @param actual Decoded account.
    /// @param expected Expected account.
    error InvalidAOAConfigAccount(address actual, address expected);

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

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy and grants the admin role.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` (controls pause/unpause).
    constructor(address policyManager, address admin) Policy(policyManager) {
        if (admin == address(0)) revert ZeroAdmin();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Pauses execution for this policy.
    ///
    /// @dev Only callable by `DEFAULT_ADMIN_ROLE`.
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpauses execution for this policy.
    ///
    /// @dev Only callable by `DEFAULT_ADMIN_ROLE`.
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
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
        return
            POLICY_MANAGER.PUBLIC_ERC6492_VALIDATOR().isValidSignatureNowAllowSideEffects(executor, digest, signature);
    }

    /// @dev Reverts if `nonce` is already used for `policyId`.
    function _requireUnusedNonce(bytes32 policyId, uint256 nonce) internal view {
        if (_usedNonces[policyId][nonce]) revert ExecutionNonceAlreadyUsed(policyId, nonce);
    }

    /// @dev Marks `nonce` as used for `policyId`.
    function _markNonceUsed(bytes32 policyId, uint256 nonce) internal {
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

    /// @inheritdoc Policy
    ///
    /// @dev AOA install hook wrapper: stores config hash, decodes `AOAConfig`, and calls `_onAOAInstall`.
    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address) internal override {
        _storeConfigHash(policyId, policyConfig);
        (AOAConfig memory aoaConfig, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        _onAOAInstall(policyId, aoaConfig, policySpecificConfig);
    }

    /// @inheritdoc Policy
    ///
    /// @dev AOA uninstall hook wrapper: enforces executor authorization.
    function _onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    ) internal virtual override {
        // Account can always uninstall without providing config.
        if (caller == account) {
            _onAOAUninstall(policyId, account, caller);
            return;
        }

        // Non-account uninstallers must provide the installed config preimage.
        _requireConfigHash(policyId, policyConfig);
        (AOAConfig memory aoaConfig,) = _decodeAOAConfig(account, policyConfig);

        // Optional auth:
        // - direct caller is executor, OR
        // - executor-signed uninstall intent (relayers allowed)
        if (caller != aoaConfig.executor) {
            (bytes memory signature, uint256 deadline) = abi.decode(uninstallData, (bytes, uint256));
            if (deadline != 0 && block.timestamp > deadline) {
                revert SignatureExpired(block.timestamp, deadline);
            }
            bytes32 digest = _hashTypedData(
                keccak256(
                    abi.encode(AOA_UNINSTALL_TYPEHASH, policyId, account, _configHashByPolicyId[policyId], deadline)
                )
            );
            if (!_isValidExecutorSig(aoaConfig.executor, digest, signature)) revert Unauthorized(caller);
        }

        _onAOAUninstall(policyId, account, aoaConfig.executor);
    }

    /// @inheritdoc Policy
    ///
    /// @dev AOA cancel hook wrapper: enforces executor authorization for pre-install cancellation.
    function _onCancel(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata cancelData,
        address caller
    ) internal override {
        // Account can always cancel.
        if (caller == account) return;

        // Non-account cancellers must be the configured executor (derivable from config) OR provide an executor signature.
        (AOAConfig memory aoaConfig,) = _decodeAOAConfig(account, policyConfig);

        if (caller != aoaConfig.executor) {
            (bytes memory signature, uint256 deadline) = abi.decode(cancelData, (bytes, uint256));
            if (deadline != 0 && block.timestamp > deadline) {
                revert SignatureExpired(block.timestamp, deadline);
            }
            bytes32 digest = _hashTypedData(
                keccak256(abi.encode(AOA_CANCEL_TYPEHASH, policyId, account, keccak256(policyConfig), deadline))
            );
            if (!_isValidExecutorSig(aoaConfig.executor, digest, signature)) revert Unauthorized(caller);
        }
    }

    /// @inheritdoc Policy
    ///
    /// @dev AOA execute hook wrapper: requires installed config, validates executor signature + nonce replay
    ///      protection for all executions, decodes canonical payload shapes, and delegates to `_onAOAExecute`.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal override whenNotPaused returns (bytes memory accountCallData, bytes memory postCallData) {
        _requireConfigHash(policyId, policyConfig);

        (AOAConfig memory aoaConfig, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        (AOAExecutionData memory aoaExecutionData, bytes memory actionData) =
            abi.decode(executionData, (AOAExecutionData, bytes));

        _requireUnusedNonce(policyId, aoaExecutionData.nonce);
        if (aoaExecutionData.deadline != 0 && block.timestamp > aoaExecutionData.deadline) {
            revert SignatureExpired(block.timestamp, aoaExecutionData.deadline);
        }

        bytes32 configHash = _configHashByPolicyId[policyId];
        bytes32 actionDataHash = keccak256(actionData);
        bytes32 executionDataHash =
            keccak256(abi.encode(actionDataHash, aoaExecutionData.nonce, aoaExecutionData.deadline));
        bytes32 digest = _getExecutionDigest(policyId, account, configHash, executionDataHash);
        if (!_isValidExecutorSig(aoaConfig.executor, digest, aoaExecutionData.signature)) revert Unauthorized(caller);
        _markNonceUsed(policyId, aoaExecutionData.nonce);

        return _onAOAExecute(policyId, aoaConfig, policySpecificConfig, actionData);
    }

    /// @notice Policy-specific install hook for AOA policies.
    ///
    /// @dev Override to initialize per-policy state.
    function _onAOAInstall(bytes32 policyId, AOAConfig memory aoaConfig, bytes memory policySpecificConfig)
        internal
        virtual
    {
        policyId;
        aoaConfig;
        policySpecificConfig;
    }

    /// @notice Policy-specific uninstall hook for AOA policies.
    ///
    /// @dev Override to clear per-policy state.
    function _onAOAUninstall(bytes32 policyId, address account, address caller) internal virtual {
        policyId;
        account;
        caller;
    }

    /// @notice Policy-specific execute hook for AOA policies.
    ///
    /// @dev Override to enforce execution authorization and build account/post-call calldata.
    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoaConfig,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);

    ////////////////////////////////////////////////////////////////
    ///                 Internal Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Requires the supplied config preimage to match the stored hash for the policyId.
    ///
    /// @param policyId Policy identifier.
    /// @param policyConfig Full config preimage bytes.
    function _requireConfigHash(bytes32 policyId, bytes calldata policyConfig) internal view {
        bytes32 expected = _configHashByPolicyId[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);
    }

    /// @notice Decodes the canonical AOA config prefix and policy-specific config.
    ///
    /// @param expectedAccount Expected account for this policyId (from the manager).
    /// @param policyConfig Full config preimage bytes.
    ///
    /// @return aoaConfig Decoded AOA config prefix.
    /// @return policySpecificConfig Remaining policy-specific config bytes.
    function _decodeAOAConfig(address expectedAccount, bytes calldata policyConfig)
        internal
        pure
        returns (AOAConfig memory aoaConfig, bytes memory policySpecificConfig)
    {
        (aoaConfig, policySpecificConfig) = abi.decode(policyConfig, (AOAConfig, bytes));
        if (aoaConfig.account != expectedAccount) revert InvalidAOAConfigAccount(aoaConfig.account, expectedAccount);
        if (aoaConfig.executor == address(0)) revert ZeroExecutor();
    }
}

