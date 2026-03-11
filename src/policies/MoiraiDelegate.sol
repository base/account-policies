// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Policy} from "./Policy.sol";
import {SingleExecutorPolicy} from "./SingleExecutorPolicy.sol";

/// @title MoiraiDelegate
///
/// @notice A one-shot delegation policy that executes a fixed calldata payload on behalf of an account
///         under at least one of two configurable conditions: a time-lock and/or an executor signature.
///
/// @dev Inherits `SingleExecutorPolicy` directly. The executor is optional (zero address means no consensus
///      required). At least one condition must be configured at install time:
///      - `unlockTimestamp > 0` — execution is gated behind a time-lock.
///      - `executor != address(0)` — execution requires a valid executor-signed intent.
///
///      Config format: `policyConfig = abi.encode(MoiraiConfig)` — NOT the nested `(SingleExecutorConfig,
///      bytes)` pattern used by `SingleExecutorAuthorizedPolicy`.
///
///      Execution data format (when executor is set): `executionData = abi.encode(SingleExecutorExecutionData,
///      bytes actionData)`.
///
///      Each policy instance may only be executed once — `_executed[policyId]` guards against replays.
contract MoiraiDelegate is SingleExecutorPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Full configuration for a MoiraiDelegate policy instance.
    struct MoiraiConfig {
        /// @dev Executor config. `executor == address(0)` means no consensus is required.
        SingleExecutorConfig singleExecutorConfig;
        /// @dev Target address for the delegated call (informational; callData encodes the full call).
        address target;
        /// @dev ETH value to send with the call.
        uint256 value;
        /// @dev ABI-encoded calldata to execute on the account.
        bytes callData;
        /// @dev Earliest timestamp (seconds) at which execution is allowed. Zero means no time-lock.
        uint256 unlockTimestamp;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Tracks whether a policy instance has already been executed.
    mapping(bytes32 policyId => bool executed) private _executed;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when a policy instance has already been executed.
    ///
    /// @param policyId Policy identifier that was already executed.
    error AlreadyExecuted(bytes32 policyId);

    /// @notice Thrown when neither `unlockTimestamp` nor `executor` is configured.
    error NoConditionSpecified();

    /// @notice Thrown when the current timestamp has not yet reached the configured unlock timestamp.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param unlockTimestamp Configured unlock timestamp in seconds.
    error UnlockTimestampNotReached(uint256 currentTimestamp, uint256 unlockTimestamp);

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy and grants the admin role.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` (controls pause/unpause).
    constructor(address policyManager, address admin) SingleExecutorPolicy(policyManager, admin) {}

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Returns whether a policy instance has been executed.
    ///
    /// @param policyId Policy identifier to check.
    ///
    /// @return True if the policy instance has been executed, false otherwise.
    function isExecuted(bytes32 policyId) external view returns (bool) {
        return _executed[policyId];
    }

    /// @notice Cancels one or more nonces, preventing future execution intents that use them.
    ///
    /// @dev Overrides the base implementation to decode `MoiraiConfig` instead of the canonical
    ///      `(SingleExecutorConfig, bytes)` shape. Only the configured executor may cancel nonces.
    ///      Already-used nonces are skipped silently for idempotency.
    ///
    ///      Not gated by `whenNotPaused` — nonce cancellation is a safety/revocation mechanism that
    ///      should always be available.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param nonces Array of nonces to cancel.
    /// @param policyConfig Full config preimage bytes (hash must match the stored config hash for `policyId`).
    function cancelNonces(bytes32 policyId, uint256[] calldata nonces, bytes calldata policyConfig) external override {
        _requireConfigHash(policyId, policyConfig);
        MoiraiConfig memory config = abi.decode(policyConfig, (MoiraiConfig));
        if (msg.sender != config.singleExecutorConfig.executor) {
            revert UnauthorizedCanceller(msg.sender, config.singleExecutorConfig.executor);
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

    /// @inheritdoc Policy
    ///
    /// @dev Decodes `MoiraiConfig`, validates that at least one condition is set, and stores the config hash.
    function _onInstall(bytes32 policyId, address, bytes calldata policyConfig, address) internal override {
        MoiraiConfig memory config = abi.decode(policyConfig, (MoiraiConfig));
        if (config.unlockTimestamp == 0 && config.singleExecutorConfig.executor == address(0)) {
            revert NoConditionSpecified();
        }
        _storeConfigHash(policyId, policyConfig);
    }

    /// @inheritdoc Policy
    ///
    /// @dev Only the bound account may uninstall. Cleans up stored state.
    function _onUninstall(bytes32 policyId, address account, bytes calldata, bytes calldata, address caller)
        internal
        override
    {
        if (caller != account) revert Unauthorized(caller);
        delete _executed[policyId];
        delete _configHashByPolicyId[policyId];
    }

    /// @inheritdoc Policy
    ///
    /// @dev During replacement the account has already authorized the operation. Allow it and clean up state.
    function _onUninstallForReplace(
        bytes32 policyId,
        address,
        bytes calldata,
        bytes calldata,
        address,
        bytes32,
        address
    ) internal override {
        delete _executed[policyId];
        delete _configHashByPolicyId[policyId];
    }

    /// @inheritdoc Policy
    ///
    /// @dev Validates config hash, checks single-execution guard, enforces time-lock and/or executor signature,
    ///      then returns the configured calldata as the account call.
    ///
    ///      When `executionData` is empty the function returns early without touching `_executed[policyId]`.
    ///      This is an intentional no-op: it does NOT consume the one-shot execution lock. Callers who want
    ///      to trigger the policy must supply non-empty `executionData`.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal override whenNotPaused returns (bytes memory accountCallData, bytes memory postCallData) {
        if (executionData.length == 0) return (accountCallData, postCallData);

        _requireConfigHash(policyId, policyConfig);

        MoiraiConfig memory config = abi.decode(policyConfig, (MoiraiConfig));

        if (_executed[policyId]) revert AlreadyExecuted(policyId);

        if (config.unlockTimestamp > 0) {
            if (block.timestamp < config.unlockTimestamp) {
                revert UnlockTimestampNotReached(block.timestamp, config.unlockTimestamp);
            }
        }

        if (config.singleExecutorConfig.executor != address(0)) {
            (SingleExecutorExecutionData memory executionData_, bytes memory actionData) =
                abi.decode(executionData, (SingleExecutorExecutionData, bytes));
            _validateAndConsumeExecutionIntent(
                policyId, account, config.singleExecutorConfig.executor, executionData_, actionData, caller
            );
        }

        _executed[policyId] = true;

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
