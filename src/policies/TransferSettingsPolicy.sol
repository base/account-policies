// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Policy} from "./Policy.sol";
import {SingleExecutorPolicy} from "./SingleExecutorPolicy.sol";

/// @title TransferSettingsPolicy
///
/// @notice A one-shot policy that executes a fixed token transfer (native ETH or ERC20) on behalf of an account
///         under at least one of two configurable conditions: a time-lock and/or an executor signature.
///
/// @dev Inherits `SingleExecutorPolicy` directly. The executor is optional (zero address means no consensus
///      required). At least one condition must be configured at install time:
///      - `unlockTimestamp > 0` — execution is gated behind a time-lock.
///      - `executor != address(0)` — execution requires a valid executor-signed intent.
///
///      The transfer parameters (`recipient`, `amount`, `tokenContract`) are fixed at install time.
///      For native ETH transfers, set `tokenContract` to `address(0)`. For ERC20 transfers, set
///      `tokenContract` to the ERC20 contract address; the policy hard-codes the `transfer` selector.
///
///      Config format: `policyConfig = abi.encode(SingleExecutorConfig, abi.encode(TransferConfig))` — the
///      canonical single-executor encoding shared across all `SingleExecutorPolicy` subclasses.
///
///      Execution data format (when executor is set): `executionData = abi.encode(SingleExecutorExecutionData,
///      bytes actionData)`.
///
///      Each policy instance may only be executed once — `executed[policyId]` guards against replays.
///
///      ERC20 transfers: `CoinbaseSmartWallet.execute` propagates inner-call reverts but does NOT inspect
///      the boolean return value of `IERC20.transfer`. Non-standard tokens (e.g. USDT-mainnet) that return
///      `false` without reverting would silently succeed from the wallet's perspective. To guard against this,
///      `_onPostExecute` reads the recipient's post-call balance and reverts with `ERC20TransferFailed` if it
///      did not increase by at least `amount`.
contract TransferSettingsPolicy is SingleExecutorPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy-specific configuration for a TransferSettingsPolicy instance.
    ///
    /// @dev Encoded as the inner `policySpecificConfig` bytes inside the canonical
    ///      `abi.encode(SingleExecutorConfig, abi.encode(TransferConfig))` envelope.
    struct TransferConfig {
        /// @dev Destination address for the transfer. Must be non-zero.
        address recipient;
        /// @dev Amount to transfer (wei for native ETH; token units for ERC20). Must be non-zero.
        uint256 amount;
        /// @dev Token contract address. `address(0)` means native ETH transfer; otherwise ERC20.
        address tokenContract;
        /// @dev Earliest timestamp (seconds) at which execution is allowed. Zero means no time-lock.
        uint256 unlockTimestamp;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Tracks whether a policy instance has already been executed.
    ///
    /// @dev `executed[policyId]` is `true` after a successful `_onExecute` call and `false` before (or after
    ///      uninstall, which deletes it). The executor can clear this bit via a signed uninstall intent.
    mapping(bytes32 policyId => bool hasExecuted) public executed;

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

    /// @notice Thrown when the configured recipient is the zero address.
    error ZeroRecipient();

    /// @notice Thrown when the configured transfer amount is zero.
    error ZeroAmount();

    /// @notice Thrown when non-empty action data is provided; this policy does not use action data.
    error UnexpectedActionData();

    /// @notice Thrown when an ERC20 transfer did not deliver the expected token amount to the recipient.
    ///
    /// @dev Fired in `_onPostExecute` when the recipient's post-call balance did not increase by
    ///      at least `amount`. Covers non-standard tokens that return `false` without reverting.
    error ERC20TransferFailed();

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
    /// @dev Decodes the canonical `(SingleExecutorConfig, bytes)` envelope, decodes the inner `TransferConfig`,
    ///      validates that at least one condition is set, validates recipient and amount, and stores the config hash.
    function _onInstall(bytes32 policyId, address, bytes calldata policyConfig) internal override {
        (SingleExecutorConfig memory singleExecutorConfig, bytes memory specificConfig) =
            _decodeSingleExecutorConfig(policyConfig);
        TransferConfig memory config = abi.decode(specificConfig, (TransferConfig));
        if (config.unlockTimestamp == 0 && singleExecutorConfig.executor == address(0)) {
            revert NoConditionSpecified();
        }
        if (config.recipient == address(0)) revert ZeroRecipient();
        if (config.amount == 0) revert ZeroAmount();
        _storeConfigHash(policyId, policyConfig);
    }

    /// @inheritdoc Policy
    ///
    /// @dev Three paths:
    ///      1. `caller == account` — fast-delete; no config or signature required. This is also the path taken by
    ///         `Policy._onUninstallForReplace`, which calls `_onUninstall(..., caller=account)`.
    ///      2. `storedConfigHash == 0` (pre-install disable) — executor signs over `keccak256(policyConfig)` to
    ///         permanently block a policyId before the account ever installs it. Reverts if `executor == address(0)`
    ///         (delay-only configs have no executor to authorize pre-install disable).
    ///      3. Post-install executor uninstall — executor signs over the stored config hash. Clearing `executed`
    ///         here is intentional; the `PolicyManager` permanently marks the policyId as uninstalled, so clearing
    ///         the bit does not enable a replay.
    ///
    ///      Non-account callers must supply `uninstallData = abi.encode(bytes signature, uint256 deadline)`.
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

        // Pre-install permanent disable: executor signs over keccak256(policyConfig).
        if (storedConfigHash == bytes32(0)) {
            (SingleExecutorConfig memory preinstallConfig,) = _decodeSingleExecutorConfig(policyConfig);
            if (preinstallConfig.executor == address(0)) revert Unauthorized(caller);
            (bytes memory sig, uint256 dl) = abi.decode(uninstallData, (bytes, uint256));
            if (dl != 0 && block.timestamp > dl) revert SignatureExpired(block.timestamp, dl);
            bytes32 preinstallDigest = _getUninstallDigest(policyId, account, keccak256(policyConfig), dl);
            if (!_isValidExecutorSig(preinstallConfig.executor, preinstallDigest, sig)) revert Unauthorized(caller);
            return; // Nothing installed to delete.
        }

        // Post-install: executor provides signed uninstall intent over stored config hash.
        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != storedConfigHash) revert PolicyConfigHashMismatch(actualConfigHash, storedConfigHash);
        (SingleExecutorConfig memory singleExecutorConfig,) = _decodeSingleExecutorConfig(policyConfig);
        if (singleExecutorConfig.executor == address(0)) revert Unauthorized(caller);
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
    ///      then constructs and returns the transfer call as the account call.
    ///
    ///      For native ETH transfers (`tokenContract == address(0)`), the account calls `execute(recipient,
    ///      amount, "")`. For ERC20 transfers, the account calls `execute(tokenContract, 0,
    ///      abi.encodeCall(IERC20.transfer, (recipient, amount)))`.
    ///
    ///      For executor-required policies (`executor != address(0)`), `executionData` is decoded to extract
    ///      the executor signature. For delay-only policies (`executor == address(0)`), `executionData` is never
    ///      inspected — only the time-lock matters.
    ///
    ///      For ERC20 transfers, `postCallData` encodes `(tokenContract, recipient, amount)` so that
    ///      `_onPostExecute` can verify the recipient's balance increased by at least `amount`.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal override whenNotPaused returns (bytes memory accountCallData, bytes memory postCallData) {
        _requireConfigHash(policyId, policyConfig);

        (SingleExecutorConfig memory singleExecutorConfig, bytes memory specificConfig) =
            _decodeSingleExecutorConfig(policyConfig);
        TransferConfig memory config = abi.decode(specificConfig, (TransferConfig));

        if (executed[policyId]) revert AlreadyExecuted(policyId);

        if (config.unlockTimestamp > 0) {
            if (block.timestamp < config.unlockTimestamp) {
                revert BeforeUnlockTimestamp(block.timestamp, config.unlockTimestamp);
            }
        }

        if (singleExecutorConfig.executor != address(0)) {
            (SingleExecutorExecutionData memory executionData_, bytes memory actionData) =
                abi.decode(executionData, (SingleExecutorExecutionData, bytes));
            if (actionData.length != 0) revert UnexpectedActionData();
            _validateAndConsumeExecutionIntent(
                policyId, account, singleExecutorConfig.executor, executionData_, actionData, caller
            );
        }

        executed[policyId] = true;

        if (config.tokenContract == address(0)) {
            // Native ETH transfer
            accountCallData =
                abi.encodeCall(CoinbaseSmartWallet.execute, (config.recipient, config.amount, new bytes(0)));
            return (accountCallData, "");
        } else {
            // ERC20 transfer
            accountCallData = abi.encodeCall(
                CoinbaseSmartWallet.execute,
                (config.tokenContract, uint256(0), abi.encodeCall(IERC20.transfer, (config.recipient, config.amount)))
            );
            // Pass token details to _onPostExecute for balance verification.
            postCallData = abi.encode(config.tokenContract, config.recipient, config.amount);
            return (accountCallData, postCallData);
        }
    }

    /// @inheritdoc Policy
    ///
    /// @dev For ERC20 transfers, verifies that the recipient's token balance increased by at least `amount`
    ///      after the account call. This guards against non-standard tokens (e.g. USDT-mainnet) that return
    ///      `false` from `transfer` without reverting — `CoinbaseSmartWallet.execute` propagates call reverts
    ///      but does not inspect the ERC20 return value. For native ETH transfers, `postCallData` is empty
    ///      and this hook is a no-op.
    ///
    /// @param postCallData ABI-encoded `(address tokenContract, address recipient, uint256 amount)` for ERC20;
    ///                     empty for native ETH.
    function _onPostExecute(bytes32, address, bytes calldata postCallData) internal view override {
        if (postCallData.length == 0) return;
        (address tokenContract, address recipient, uint256 amount) =
            abi.decode(postCallData, (address, address, uint256));
        uint256 balance = IERC20(tokenContract).balanceOf(recipient);
        if (balance < amount) revert ERC20TransferFailed();
    }

    /// @dev Returns the EIP-712 domain name and version used for executor signature verification.
    ///
    /// @return name    Domain name (`"Transfer Settings Policy"`).
    /// @return version Domain version (`"1"`).
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Transfer Settings Policy";
        version = "1";
    }
}
