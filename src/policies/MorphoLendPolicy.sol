// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {AccessControl} from "openzeppelin-contracts/contracts/access/AccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "../PublicERC6492Validator.sol";
import {IMorphoVault} from "../interfaces/morpho/IMorphoVault.sol";
import {Policy} from "./Policy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @notice Morpho vault deposit policy.
/// @dev Intentionally conservative: fixed vault, fixed receiver (the account), bounded amount, approval reset,
///      and optional cumulative cap.
contract MorphoLendPolicy is EIP712, Policy, AccessControl, Pausable {
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error ZeroAdmin();
    error ZeroAmount();
    error ZeroVault();
    error ZeroExecutor();
    error Unauthorized(address caller);
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);
    error ZeroNonce();

    bytes32 public constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash)");

    mapping(bytes32 policyId => mapping(address account => bytes32 configHash)) internal _configHashes;
    RecurringAllowance.State internal _depositLimitState;
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    struct Config {
        address executor;
        address vault;
        RecurringAllowance.Limit depositLimit;
    }

    struct LendData {
        uint256 assets; // The amount of assets to supply, in the loan token's smallest unit (i.e. ERC20 decimals)
        uint256 nonce; // Policy-defined execution nonce (used for replay protection and for signed execution intents).
    }

    struct PolicyData {
        LendData data;
        bytes signature;
    }

    constructor(address policyManager, address admin) Policy(policyManager) {
        if (admin == address(0)) revert ZeroAdmin();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    function _getInstallWindowAsLimitBounds(bytes32 policyId) internal view returns (uint48 start, uint48 end) {
        (, , , uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.getPolicyRecord(address(this), policyId);
        start = uint48(validAfter);
        end = validUntil == 0 ? type(uint48).max : uint48(validUntil);
    }

    function _applyInstallWindowBoundsIfUnset(bytes32 policyId, RecurringAllowance.Limit memory limit)
        internal
        view
        returns (RecurringAllowance.Limit memory)
    {
        // Sentinel: if config leaves both timestamps zero, bind allowance to the policy install window.
        if (limit.start == 0 && limit.end == 0) {
            (limit.start, limit.end) = _getInstallWindowAsLimitBounds(policyId);
        }
        return limit;
    }

    /// @notice Return recurring deposit limit usage for a policy instance.
    /// @dev Requires the config preimage so the contract can decode `depositLimit` without storing it.
    function getDepositLimitPeriodUsage(bytes32 policyId, address account, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        bytes32 configHash = _configHashes[policyId][account];
        bytes32 actual = keccak256(policyConfig);
        if (configHash != actual) revert PolicyConfigHashMismatch(configHash, actual);

        Config memory cfg = abi.decode(policyConfig, (Config));
        cfg.depositLimit = _applyInstallWindowBoundsIfUnset(policyId, cfg.depositLimit);
        lastUpdated = RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(_depositLimitState, policyId, cfg.depositLimit);
    }

    /// @notice Return the last stored recurring deposit usage for a policy instance.
    function getDepositLimitLastUpdated(bytes32 policyId) external view returns (RecurringAllowance.PeriodUsage memory) {
        return RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
    }

    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        internal
        override
    {
        caller;
        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.executor == address(0)) revert ZeroExecutor();
        if (cfg.vault == address(0)) revert ZeroVault();
        _configHashes[policyId][account] = keccak256(policyConfig);
    }

    function _onUninstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        internal
        override
    {
        // Account can always uninstall (config optional).
        if (caller == account) {
            delete _configHashes[policyId][account];
            return;
        }

        // Non-account uninstallers must provide the installed config preimage.
        bytes32 expectedHash = _configHashes[policyId][account];
        bytes32 actualHash = keccak256(policyConfig);
        if (expectedHash != actualHash) revert PolicyConfigHashMismatch(actualHash, expectedHash);

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (caller != cfg.executor) revert Unauthorized(caller);

        delete _configHashes[policyId][account];
    }

    function _onCancel(bytes32, address account, bytes calldata policyConfig, address caller) internal view override {
        // Account can always cancel.
        if (caller == account) return;

        // Executor can cancel if it can be derived from the config.
        Config memory cfg = abi.decode(policyConfig, (Config));
        if (caller != cfg.executor) revert Unauthorized(caller);
    }

    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal override whenNotPaused returns (bytes memory accountCallData, bytes memory postCallData) {
        bytes32 configHash = _configHashes[policyId][account];
        if (configHash != keccak256(policyConfig)) {
            revert PolicyConfigHashMismatch(configHash, keccak256(policyConfig));
        }

        Config memory cfg = abi.decode(policyConfig, (Config));
        PolicyData memory pd = abi.decode(policyData, (PolicyData));

        if (pd.data.assets == 0) revert ZeroAmount();
        if (pd.data.nonce == 0) revert ZeroNonce();
        if (_usedNonces[policyId][pd.data.nonce]) revert ExecutionNonceAlreadyUsed(policyId, pd.data.nonce);

        bytes32 payloadHash = keccak256(abi.encode(pd.data));
        bytes32 digest = _getExecutionDigest(policyId, account, configHash, payloadHash);
        bool ok = POLICY_MANAGER.PUBLIC_ERC6492_VALIDATOR()
            .isValidSignatureNowAllowSideEffects(cfg.executor, digest, pd.signature);
        if (!ok) revert Unauthorized(caller);

        _usedNonces[policyId][pd.data.nonce] = true;

        RecurringAllowance.Limit memory depositLimit = _applyInstallWindowBoundsIfUnset(policyId, cfg.depositLimit);
        RecurringAllowance.useLimit(_depositLimitState, policyId, depositLimit, pd.data.assets);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildVaultDepositCall(cfg, account, pd.data.assets);

        // Build wallet call plan:
        // - approve
        // - protocol call
        if (approvalToken != address(0) && approvalSpender != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, pd.data.assets)
            });
            calls[1] = CoinbaseSmartWallet.Call({target: target, value: value, data: callData});
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        } else {
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, callData);
        }

        postCallData = "";
    }

    function _getExecutionDigest(bytes32 policyId, address account, bytes32 configHash, bytes32 policyDataHash)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedData(keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, account, configHash, policyDataHash)));
    }

    function _buildVaultDepositCall(Config memory cfg, address receiver, uint256 assets)
        internal
        view
        returns (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender)
    {
        target = cfg.vault;
        value = 0;

        approvalToken = IMorphoVault(cfg.vault).asset();
        approvalSpender = cfg.vault;
        callData = abi.encodeWithSelector(IMorphoVault.deposit.selector, assets, receiver);
        return (target, value, callData, approvalToken, approvalSpender);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Lend Policy";
        version = "1";
    }
}

