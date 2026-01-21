// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "../PublicERC6492Validator.sol";
import {PolicyTypes} from "../PolicyTypes.sol";
import {Policy} from "./Policy.sol";

interface IPolicyManagerLike {
    function getPolicyBindingStructHash(PolicyTypes.PolicyBinding calldata binding) external pure returns (bytes32);
    function PUBLIC_ERC6492_VALIDATOR() external view returns (PublicERC6492Validator);
}

/// @dev Morpho Blue `MarketParams` struct.
struct MarketParams {
    address loanToken;
    address collateralToken;
    address oracle;
    address irm;
    uint256 lltv;
}

/// @dev Minimal Morpho Blue interface used by this policy.
interface IMorpho {
    function supply(
        MarketParams calldata marketParams,
        uint256 assets,
        uint256 shares,
        address onBehalf,
        bytes calldata data
    ) external returns (uint256 assetsSupplied, uint256 sharesSupplied);
}

/// @notice Morpho lend-only policy (supply-only).
/// @dev Intentionally conservative: fixed market, fixed onBehalf (the account), bounded amount, approval reset,
///      and optional cumulative cap.
contract MorphoLendPolicy is EIP712, Policy {
    error InvalidSender(address sender, address expected);
    error InvalidPolicyConfigAccount(address actual, address expected);
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error ZeroAmount();
    error AmountTooHigh(uint256 amount, uint256 maxAmount);
    error CumulativeAmountTooHigh(uint256 nextTotal, uint256 maxTotal);
    error ZeroMorpho();
    error ZeroExecutor();
    error InvalidMarket();
    error Unauthorized(address caller);
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);
    error ZeroNonce();

    address public immutable POLICY_MANAGER;
    // TODO: do we create a shared policy base class for policies that want to enable signature-based execution?
    bytes32 public constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash)");

    // Cumulative accounting is per policy instance (policyId) in loan-token units.
    // We only ever increment these (conservative).
    mapping(bytes32 policyId => uint256) internal _cumulativeSupplied;
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    struct Config {
        address account;
        address executor;
        address morpho;
        MarketParams marketParams;
        uint256 maxSupply;
        uint256 maxCumulativeSupply; // Optional cumulative budget (denominated in the loan token's units). 0 disables the cumulative cap.
    }

    struct LendData {
        uint256 assets; // The amount of assets to supply, in the loan token's smallest unit (i.e. ERC20 decimals)
        uint256 nonce; // Policy-defined execution nonce (used for replay protection and for signed execution intents).
    }

    struct PolicyData {
        LendData data;
        bytes signature;
    }

    modifier requireSender(address sender) {
        _requireSender(sender);
        _;
    }

    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }

    constructor(address policyManager) {
        POLICY_MANAGER = policyManager;
    }

    function onInstall(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId, bytes calldata policyConfig)
        external
        view
        override
        requireSender(POLICY_MANAGER)
    {
        binding;
        policyId;
        policyConfig;
    }

    function onRevoke(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId)
        external
        view
        override
        requireSender(POLICY_MANAGER)
    {
        binding;
        policyId;
    }

    function onExecute(
        PolicyTypes.PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    )
        external
        override
        requireSender(POLICY_MANAGER)
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        bytes32 actualConfigHash = keccak256(policyConfig);
        if (actualConfigHash != binding.policyConfigHash) {
            revert PolicyConfigHashMismatch(actualConfigHash, binding.policyConfigHash);
        }

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.account != binding.account) revert InvalidPolicyConfigAccount(cfg.account, binding.account);
        if (cfg.executor == address(0)) revert ZeroExecutor();
        if (cfg.morpho == address(0)) revert ZeroMorpho();
        if (cfg.marketParams.loanToken == address(0) || cfg.marketParams.collateralToken == address(0)) {
            revert InvalidMarket();
        }

        PolicyData memory pd = abi.decode(policyData, (PolicyData));
        if (pd.data.assets == 0) revert ZeroAmount();
        if (pd.data.nonce == 0) revert ZeroNonce();

        if (pd.data.assets > cfg.maxSupply) revert AmountTooHigh(pd.data.assets, cfg.maxSupply);

        bytes32 policyId = IPolicyManagerLike(POLICY_MANAGER).getPolicyBindingStructHash(binding);
        if (_usedNonces[policyId][pd.data.nonce]) revert ExecutionNonceAlreadyUsed(policyId, pd.data.nonce);
        _usedNonces[policyId][pd.data.nonce] = true;

        if (caller != cfg.executor) {
            bytes32 payloadHash = keccak256(abi.encode(pd.data));
            bytes32 digest = _getExecutionDigest(policyId, binding, payloadHash);
            bool ok = IPolicyManagerLike(POLICY_MANAGER).PUBLIC_ERC6492_VALIDATOR()
                .isValidSignatureNowAllowSideEffects(cfg.executor, digest, pd.signature);
            if (!ok) revert Unauthorized(caller);
        }

        _consumeBudget(policyId, cfg, pd.data.assets);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildMorphoCall(cfg, pd.data.assets);

        // Build wallet call plan:
        // - approve
        // - protocol call
        // - approve(0)
        if (approvalToken != address(0) && approvalSpender != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, pd.data.assets)
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

    function _consumeBudget(bytes32 policyId, Config memory cfg, uint256 assets) internal {
        if (cfg.maxCumulativeSupply == 0) return;

        uint256 nextTotal = _cumulativeSupplied[policyId] + assets;
        if (nextTotal > cfg.maxCumulativeSupply) revert CumulativeAmountTooHigh(nextTotal, cfg.maxCumulativeSupply);
        _cumulativeSupplied[policyId] = nextTotal;
    }

    function _buildMorphoCall(Config memory cfg, uint256 assets)
        internal
        pure
        returns (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender)
    {
        target = cfg.morpho;
        value = 0;

        approvalToken = cfg.marketParams.loanToken;
        approvalSpender = cfg.morpho;
        callData = abi.encodeWithSelector(IMorpho.supply.selector, cfg.marketParams, assets, 0, cfg.account, bytes(""));
        return (target, value, callData, approvalToken, approvalSpender);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Lend Policy";
        version = "1";
    }
}

