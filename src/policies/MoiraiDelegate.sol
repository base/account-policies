// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Policy} from "./Policy.sol";
import {SingleExecutorPolicy} from "./SingleExecutorPolicy.sol";

/// @title MoiraiDelegate
///
/// @notice A one-shot delegation policy that executes a fixed call (target, value, calldata) on behalf of
///         an account under at least one of two configurable conditions: a time-lock and/or an executor signature.
///
/// @dev Inherits `SingleExecutorPolicy` directly. The executor is optional (zero address means no consensus
///      required). At least one condition must be configured at install time:
///      - `unlockTimestamp > 0` — execution is gated behind a time-lock.
///      - `executor != address(0)` — execution requires a valid executor-signed intent.
///
///      Config format: `policyConfig = abi.encode(SingleExecutorConfig, abi.encode(MoiraiConfig))` — the canonical
///      single-executor encoding shared across all `SingleExecutorPolicy` subclasses.
///
///      Execution data format (when executor is set): `executionData = abi.encode(SingleExecutorExecutionData,
///      bytes actionData)`.
///
///      Each policy instance may only be executed once — `executed[policyId]` guards against replays.
contract MoiraiDelegate is SingleExecutorPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy-specific configuration for a MoiraiDelegate instance.
    ///
    /// @dev Encoded as the inner `policySpecificConfig` bytes inside the canonical
    ///      `abi.encode(SingleExecutorConfig, abi.encode(MoiraiConfig))` envelope.
    struct MoiraiConfig {
        /// @dev Target address for the delegated call.
        address target;
        /// @dev ETH value to send with the call.
        uint256 value;
        /// @dev Calldata to pass to `target`.
        bytes callData;
        /// @dev Earliest timestamp (seconds) at which execution is allowed. Zero means no time-lock.
        uint256 unlockTimestamp;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Tracks whether a policy instance has already been executed.
    mapping(bytes32 policyId => bool executed) public executed;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when a policy instance has already been executed.
    ///
    /// @param policyId Policy identifier that was already executed.
    error AlreadyExecuted(bytes32 policyId);

    /// @notice Thrown when neither `unlockTimestamp` nor executor is configured.
    error NoConditionSpecified();

    /// @notice Thrown when the current timestamp has not yet reached the configured unlock timestamp.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param unlockTimestamp Configured unlock timestamp in seconds.
    error BeforeUnlockTimestamp(uint256 currentTimestamp, uint256 unlockTimestamp);

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy and grants the admin role.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` and `PAUSER_ROLE`.
    constructor(address policyManager, address admin) SingleExecutorPolicy(policyManager, admin) {}

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc Policy
    ///
    /// @dev Decodes the canonical `(SingleExecutorConfig, bytes)` envelope, decodes the inner `MoiraiConfig`,
    ///      validates that at least one condition is set, and stores the config hash.
    function _onInstall(bytes32 policyId, address, bytes calldata policyConfig) internal override {
        (SingleExecutorConfig memory singleExecutorConfig, bytes memory specificConfig) =
            _decodeSingleExecutorConfig(policyConfig);
        MoiraiConfig memory config = abi.decode(specificConfig, (MoiraiConfig));
        if (config.unlockTimestamp == 0 && singleExecutorConfig.executor == address(0)) {
            revert NoConditionSpecified();
        }
        _storeConfigHash(policyId, policyConfig);
    }

    /// @inheritdoc Policy
    ///
    /// @dev Account callers clear stored state immediately. Non-account callers (executor) must provide
    ///      a signed uninstall intent (`abi.encode(signature, deadline)`) over the stored config hash.
    function _onUninstall(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata uninstallData,
        address caller
    ) internal override {
        if (caller == account) {
            delete executed[policyId];
            delete _configHashByPolicyId[policyId];
            return;
        }

        bytes32 storedConfigHash = _configHashByPolicyId[policyId];

        // Pre-install permanent disable: signed by executor over policyConfig hash.
        if (storedConfigHash == bytes32(0)) {
            (SingleExecutorConfig memory preinstallConfig,) = _decodeSingleExecutorConfig(policyConfig);
            (bytes memory sig, uint256 dl) = abi.decode(uninstallData, (bytes, uint256));
            if (dl != 0 && block.timestamp > dl) revert SignatureExpired(block.timestamp, dl);
            bytes32 preinstallDigest = _getUninstallDigest(policyId, account, keccak256(policyConfig), dl);
            if (!_isValidExecutorSig(preinstallConfig.executor, preinstallDigest, sig)) revert Unauthorized(caller);
            return; // Nothing installed to delete.
        }

        // Post-install: executor provides signed uninstall intent over stored config hash.
        _requireConfigHash(policyId, policyConfig);
        (SingleExecutorConfig memory singleExecutorConfig,) = _decodeSingleExecutorConfig(policyConfig);
        (bytes memory signature, uint256 deadline) = abi.decode(uninstallData, (bytes, uint256));
        if (deadline != 0 && block.timestamp > deadline) revert SignatureExpired(block.timestamp, deadline);
        bytes32 digest = _getUninstallDigest(policyId, account, storedConfigHash, deadline);
        if (!_isValidExecutorSig(singleExecutorConfig.executor, digest, signature)) revert Unauthorized(caller);

        delete executed[policyId];
        delete _configHashByPolicyId[policyId];
    }

    /// @inheritdoc Policy
    ///
    /// @dev Validates config hash, checks single-execution guard, enforces time-lock and/or executor signature,
    ///      then returns the configured calldata as the account call.
    ///
    ///      When `executionData` is empty the function returns early without touching `executed[policyId]`.
    ///      This is an intentional no-op: it does NOT consume the one-shot execution lock. Callers who want
    ///      to trigger the policy must supply non-empty `executionData`.
    ///
    ///      For delay-only policies (`executor == address(0)`), the content of `executionData` is
    ///      ignored entirely — only its non-zero length is checked. Any non-empty bytes trigger execution
    ///      once the time-lock is met. The actual call parameters (`target`, `value`, `callData`) are always
    ///      taken from `policyConfig`, not from `executionData`.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal override whenNotPaused returns (bytes memory accountCallData, bytes memory postCallData) {
        if (executionData.length == 0) return (accountCallData, postCallData);
        _requireConfigHash(policyId, policyConfig);

        (SingleExecutorConfig memory singleExecutorConfig, bytes memory specificConfig) =
            _decodeSingleExecutorConfig(policyConfig);
        MoiraiConfig memory config = abi.decode(specificConfig, (MoiraiConfig));

        if (executed[policyId]) revert AlreadyExecuted(policyId);

        if (config.unlockTimestamp > 0) {
            if (block.timestamp < config.unlockTimestamp) {
                revert BeforeUnlockTimestamp(block.timestamp, config.unlockTimestamp);
            }
        }

        if (singleExecutorConfig.executor != address(0)) {
            (SingleExecutorExecutionData memory executionData_, bytes memory actionData) =
                abi.decode(executionData, (SingleExecutorExecutionData, bytes));
            _validateAndConsumeExecutionIntent(
                policyId, account, singleExecutorConfig.executor, executionData_, actionData, caller
            );
        }

        executed[policyId] = true;

        accountCallData =
            abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, config.target, config.value, config.callData);
        return (accountCallData, "");
    }

    /// @dev Returns the EIP-712 domain name and version used for executor signature verification.
    ///
    /// @return name    Domain name (`"Moirai Delegate"`).
    /// @return version Domain version (`"1"`).
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Moirai Delegate";
        version = "1";
    }
}
