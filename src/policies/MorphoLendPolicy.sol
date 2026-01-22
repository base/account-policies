// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PolicyTypes} from "../PolicyTypes.sol";
import {AOAPolicy} from "./AOAPolicy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

interface IPolicyManagerLike {
    function getPolicyBindingStructHash(PolicyTypes.PolicyBinding calldata binding) external pure returns (bytes32);
}

/// @dev Minimal vault interface (ERC-4626 style) used by this policy.
interface IMorphoVault {
    function asset() external view returns (address);
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
}

/// @notice Morpho vault deposit policy.
/// @dev Intentionally conservative: fixed vault, fixed receiver (the account), bounded amount, approval reset,
///      and optional cumulative cap.
contract MorphoLendPolicy is EIP712, AOAPolicy {
    error ZeroAmount();
    error ZeroVault();
    error Unauthorized(address caller);
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);
    error ZeroNonce();

    // TODO: do we create a shared policy base class for policies that want to enable signature-based execution?
    bytes32 public constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash)");

    RecurringAllowance.State internal _depositLimitState;
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    struct MorphoConfig {
        address vault;
        RecurringAllowance.Limit depositLimit;
    }

    struct LendData {
        uint256 assets; // The amount of assets to supply, in the loan token's smallest unit (i.e. ERC20 decimals)
        uint256 nonce; // Policy-defined execution nonce (used for replay protection and for signed execution intents).
    }

    constructor(address policyManager) AOAPolicy(policyManager) {}

    function _onAOAExecute(
        PolicyTypes.PolicyBinding calldata binding,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        MorphoConfig memory cfg = abi.decode(policySpecificConfig, (MorphoConfig));
        if (cfg.vault == address(0)) revert ZeroVault();

        LendData memory ld = abi.decode(actionData, (LendData));
        if (ld.assets == 0) revert ZeroAmount();
        if (ld.nonce == 0) revert ZeroNonce();

        bytes32 policyId = IPolicyManagerLike(POLICY_MANAGER).getPolicyBindingStructHash(binding);
        if (_usedNonces[policyId][ld.nonce]) revert ExecutionNonceAlreadyUsed(policyId, ld.nonce);

        bytes32 payloadHash = keccak256(actionData);
        bytes32 digest = _getExecutionDigest(policyId, binding, payloadHash);
        if (!_isValidExecutorSig(aoa.executor, digest, signature)) revert Unauthorized(caller);

        _usedNonces[policyId][ld.nonce] = true;

        RecurringAllowance.useLimit(_depositLimitState, policyId, cfg.depositLimit, ld.assets);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildVaultDepositCall(cfg, aoa.account, ld.assets);

        if (approvalToken != address(0) && approvalSpender != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, ld.assets)
            });
            calls[1] = CoinbaseSmartWallet.Call({target: target, value: value, data: callData});
            calls[2] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, 0)
            });
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        } else {
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, callData);
        }

        postCallData = "";
    }

    function _getExecutionDigest(bytes32 policyId, PolicyTypes.PolicyBinding calldata binding, bytes32 policyDataHash)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedData(
            keccak256(
                abi.encode(EXECUTION_TYPEHASH, policyId, binding.account, binding.policyConfigHash, policyDataHash)
            )
        );
    }

    function _buildVaultDepositCall(MorphoConfig memory cfg, address receiver, uint256 assets)
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

