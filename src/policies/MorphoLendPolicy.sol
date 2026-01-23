// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "../PublicERC6492Validator.sol";
import {Policy} from "./Policy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @dev Minimal vault interface (ERC-4626 style) used by this policy.
interface IMorphoVault {
    function asset() external view returns (address);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
}

/// @notice Morpho vault deposit policy.
/// @dev Intentionally conservative: fixed vault, fixed receiver (the account), bounded amount, approval reset,
///      and optional cumulative cap.
contract MorphoLendPolicy is EIP712, Policy {
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
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

    constructor(address policyManager) Policy(policyManager) {}

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

    function _onRevoke(bytes32 policyId, address account, address caller) internal override {
        if (caller != account) revert Unauthorized(caller);
        delete _configHashes[policyId][account];
    }

    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
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

        RecurringAllowance.useLimit(_depositLimitState, policyId, cfg.depositLimit, pd.data.assets);

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

