// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {PublicERC6492Validator} from "../PublicERC6492Validator.sol";
import {PermissionTypes} from "../PermissionTypes.sol";
import {Policy} from "./Policy.sol";

interface IPolicyManagerLike {
    function getInstallStructHash(PermissionTypes.Install calldata install) external pure returns (bytes32);
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
contract LendingPolicy is Policy {
    error InvalidSender(address sender, address expected);
    error InvalidPolicyConfigAccount(address actual, address expected);
    error ZeroAmount();
    error AmountTooHigh(uint256 amount, uint256 maxAmount);
    error CumulativeAmountTooHigh(uint256 nextTotal, uint256 maxTotal);
    error BeforeValidAfter(uint48 currentTimestamp, uint48 validAfter);
    error AfterValidUntil(uint48 currentTimestamp, uint48 validUntil);
    error ZeroMorpho();
    error ZeroAuthority();
    error InvalidMarket();
    error Unauthorized(address caller);

    address public immutable POLICY_MANAGER;

    // Cumulative accounting is per policy instance (policyId) in loan-token units.
    // We only ever increment these (conservative).
    mapping(bytes32 policyId => uint256) internal _cumulativeSupplied;

    struct Config {
        address account;
        address authority;
        address morpho;
        MarketParams marketParams;

        uint256 maxSupply;

        // Optional cumulative budget (denominated in the loan token's units). 0 disables the cumulative cap.
        uint256 maxCumulativeSupply;

        uint48 validAfter;
        uint48 validUntil;
    }

    struct PolicyData {
        uint256 assets; // The amount of assets to supply, in the loan token's smallest unit (i.e. ERC20 decimals)
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

    function authorize(
        PermissionTypes.Install calldata install,
        uint256 execNonce,
        bytes calldata policyConfig,
        bytes calldata policyData,
        bytes32 execDigest,
        address caller,
        bytes calldata authorizationData
    ) external override requireSender(POLICY_MANAGER) {
        install;
        execNonce;
        policyData;

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.authority == address(0)) revert ZeroAuthority();

        // Allow direct calls by the configured authority, otherwise require a signature from it.
        if (caller == cfg.authority) return;

        bool ok = IPolicyManagerLike(POLICY_MANAGER).PUBLIC_ERC6492_VALIDATOR().isValidSignatureNowAllowSideEffects(
            cfg.authority, execDigest, authorizationData
        );
        if (!ok) revert Unauthorized(caller);
    }

    function onExecute(
        PermissionTypes.Install calldata install,
        uint256 execNonce,
        bytes calldata policyConfig,
        bytes calldata policyData
    )
        external
        override
        requireSender(POLICY_MANAGER)
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        execNonce;

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.account != install.account) revert InvalidPolicyConfigAccount(cfg.account, install.account);
        if (cfg.authority == address(0)) revert ZeroAuthority();
        if (cfg.morpho == address(0)) revert ZeroMorpho();
        if (cfg.marketParams.loanToken == address(0) || cfg.marketParams.collateralToken == address(0)) {
            revert InvalidMarket();
        }

        uint48 currentTimestamp = uint48(block.timestamp);
        if (cfg.validAfter != 0 && currentTimestamp < cfg.validAfter) {
            revert BeforeValidAfter(currentTimestamp, cfg.validAfter);
        }
        if (cfg.validUntil != 0 && currentTimestamp >= cfg.validUntil) {
            revert AfterValidUntil(currentTimestamp, cfg.validUntil);
        }

        PolicyData memory data = abi.decode(policyData, (PolicyData));
        if (data.assets == 0) revert ZeroAmount();

        if (data.assets > cfg.maxSupply) revert AmountTooHigh(data.assets, cfg.maxSupply);

        bytes32 policyId = IPolicyManagerLike(POLICY_MANAGER).getInstallStructHash(install);
        _consumeBudget(policyId, cfg, data.assets);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildMorphoCall(cfg, data.assets);

        // Build wallet call plan:
        // - approve
        // - protocol call
        // - approve(0)
        if (approvalToken != address(0) && approvalSpender != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, data.assets)
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
}

