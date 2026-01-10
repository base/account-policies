// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {PermissionTypes} from "../PermissionTypes.sol";
import {Policy} from "./Policy.sol";
import {ILendingAdapter} from "./adapters/ILendingAdapter.sol";

interface IPermissionManagerLike {
    function getInstallStructHash(PermissionTypes.Install calldata install) external pure returns (bytes32);
}

/// @notice Generic lending policy built around an adapter (Aave/Compound/Morpho/etc.).
/// @dev This is intentionally conservative: fixed adapter + fixed asset allowlist + per-action maxes + optional HF
/// check.
contract LendingPolicy is Policy {
    error InvalidSender(address sender, address expected);
    error InvalidPolicyConfigAccount(address actual, address expected);
    error InvalidAction();
    error InvalidAsset(address asset);
    error ZeroAmount();
    error AmountTooHigh(uint256 amount, uint256 maxAmount);
    error CumulativeAmountTooHigh(uint256 nextTotal, uint256 maxTotal);
    error BeforeValidAfter(uint48 currentTimestamp, uint48 validAfter);
    error AfterValidUntil(uint48 currentTimestamp, uint48 validUntil);
    error ZeroAdapter();
    error ZeroAuthority();
    error HealthFactorTooLow(uint256 actual, uint256 minRequired);

    address public immutable PERMISSION_MANAGER;

    // Cumulative accounting is per policy instance (policyId) and per asset.
    // We only ever increment these (conservative): Withdraw/Repay do not “refund” budget.
    mapping(bytes32 policyId => mapping(address asset => uint256)) internal _cumulativeSupplied;
    mapping(bytes32 policyId => mapping(address asset => uint256)) internal _cumulativeBorrowed;

    struct Config {
        address account;
        address authority;
        address adapter;
        bytes adapterConfig;

        address[] allowedAssets;

        uint256 maxSupply;
        uint256 maxWithdraw;
        uint256 maxBorrow;
        uint256 maxRepay;

        // Optional cumulative budgets (per-asset, denominated in the asset's units).
        // 0 disables the cumulative cap.
        uint256 maxCumulativeSupply;
        uint256 maxCumulativeBorrow;

        uint256 minHealthFactor; // 0 disables post-check
        bool resetApprovals;

        uint48 validAfter;
        uint48 validUntil;
    }

    struct PolicyData {
        ILendingAdapter.Action action;
        address asset;
        uint256 amount;
        bytes actionData;
    }

    modifier requireSender(address sender) {
        _requireSender(sender);
        _;
    }

    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }

    constructor(address permissionManager) {
        PERMISSION_MANAGER = permissionManager;
    }

    function authority(bytes calldata policyConfig) external pure override returns (address) {
        Config memory cfg = abi.decode(policyConfig, (Config));
        return cfg.authority;
    }

    function onExecute(
        PermissionTypes.Install calldata install,
        uint256 execNonce,
        bytes calldata policyConfig,
        bytes calldata policyData
    )
        external
        override
        requireSender(PERMISSION_MANAGER)
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        execNonce;

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.account != install.account) revert InvalidPolicyConfigAccount(cfg.account, install.account);
        if (cfg.adapter == address(0)) revert ZeroAdapter();
        if (cfg.authority == address(0)) revert ZeroAuthority();

        uint48 currentTimestamp = uint48(block.timestamp);
        if (cfg.validAfter != 0 && currentTimestamp < cfg.validAfter) {
            revert BeforeValidAfter(currentTimestamp, cfg.validAfter);
        }
        if (cfg.validUntil != 0 && currentTimestamp >= cfg.validUntil) {
            revert AfterValidUntil(currentTimestamp, cfg.validUntil);
        }

        PolicyData memory data = abi.decode(policyData, (PolicyData));
        if (data.amount == 0) revert ZeroAmount();
        _requireAllowedAsset(cfg.allowedAssets, data.asset);

        uint256 maxAmount = _maxForAction(cfg, data.action);
        if (data.amount > maxAmount) revert AmountTooHigh(data.amount, maxAmount);

        bytes32 policyId = IPermissionManagerLike(PERMISSION_MANAGER).getInstallStructHash(install);
        _consumeBudget(policyId, cfg, data);

        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) = ILendingAdapter(
                cfg.adapter
            ).buildCall(cfg.account, data.action, data.asset, data.amount, cfg.adapterConfig, data.actionData);

        // Build wallet call plan:
        // - approve (optional)
        // - protocol call
        // - approve(0) (optional)
        if (approvalToken != address(0) && approvalSpender != address(0)) {
            uint256 n = cfg.resetApprovals ? 3 : 2;
            CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](n);
            calls[0] = CoinbaseSmartWallet.Call({
                target: approvalToken,
                value: 0,
                data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, data.amount)
            });
            calls[1] = CoinbaseSmartWallet.Call({target: target, value: value, data: callData});
            if (cfg.resetApprovals) {
                calls[2] = CoinbaseSmartWallet.Call({
                    target: approvalToken,
                    value: 0,
                    data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, 0)
                });
            }
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        } else {
            accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, callData);
        }

        if (cfg.minHealthFactor != 0) {
            postCallData = abi.encodeWithSelector(
                this.afterExecute.selector, cfg.adapter, cfg.account, cfg.minHealthFactor, cfg.adapterConfig
            );
        } else {
            postCallData = "";
        }
    }

    function afterExecute(address adapter, address account, uint256 minHealthFactor, bytes calldata adapterConfig)
        external
        view
        requireSender(PERMISSION_MANAGER)
    {
        uint256 hf = ILendingAdapter(adapter).healthFactor(account, adapterConfig);
        if (hf < minHealthFactor) revert HealthFactorTooLow(hf, minHealthFactor);
    }

    function _maxForAction(Config memory cfg, ILendingAdapter.Action action) internal pure returns (uint256) {
        if (action == ILendingAdapter.Action.Supply) return cfg.maxSupply;
        if (action == ILendingAdapter.Action.Withdraw) return cfg.maxWithdraw;
        if (action == ILendingAdapter.Action.Borrow) return cfg.maxBorrow;
        if (action == ILendingAdapter.Action.Repay) return cfg.maxRepay;
        revert InvalidAction();
    }

    function _consumeBudget(bytes32 policyId, Config memory cfg, PolicyData memory data) internal {
        if (data.action == ILendingAdapter.Action.Supply && cfg.maxCumulativeSupply != 0) {
            uint256 nextTotal = _cumulativeSupplied[policyId][data.asset] + data.amount;
            if (nextTotal > cfg.maxCumulativeSupply) {
                revert CumulativeAmountTooHigh(nextTotal, cfg.maxCumulativeSupply);
            }
            _cumulativeSupplied[policyId][data.asset] = nextTotal;
            return;
        }

        if (data.action == ILendingAdapter.Action.Borrow && cfg.maxCumulativeBorrow != 0) {
            uint256 nextTotal = _cumulativeBorrowed[policyId][data.asset] + data.amount;
            if (nextTotal > cfg.maxCumulativeBorrow) {
                revert CumulativeAmountTooHigh(nextTotal, cfg.maxCumulativeBorrow);
            }
            _cumulativeBorrowed[policyId][data.asset] = nextTotal;
            return;
        }
    }

    function _requireAllowedAsset(address[] memory allowedAssets, address asset) internal pure {
        for (uint256 i; i < allowedAssets.length; i++) {
            if (allowedAssets[i] == asset) return;
        }
        revert InvalidAsset(asset);
    }
}

