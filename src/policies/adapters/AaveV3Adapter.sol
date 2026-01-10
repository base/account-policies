// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ILendingAdapter} from "./ILendingAdapter.sol";

/// @dev Aave v3 `IPool`-like interface (partial).
interface IAaveV3Pool {
    function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)
        external;
    function repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf)
        external
        returns (uint256);

    function getUserAccountData(address user)
        external
        view
        returns (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        );
}

/// @notice Minimal Aave v3 adapter for LendingPolicy.
/// @dev Assumes Aave v3-style Pool interface (supply/withdraw/borrow/repay + getUserAccountData healthFactor).
contract AaveV3Adapter is ILendingAdapter {
    error InvalidAdapterConfig();
    error InvalidRateMode(uint8 rateMode);
    error InvalidAction();

    struct AdapterConfig {
        address pool;
        uint8 interestRateMode; // 1 = stable, 2 = variable (Aave convention)
        uint16 referralCode;
    }

    function buildCall(
        address account,
        Action action,
        address asset,
        uint256 amount,
        bytes calldata adapterConfig,
        bytes calldata actionData
    )
        external
        view
        returns (address target, uint256 value, bytes memory data, address approvalToken, address approvalSpender)
    {
        actionData; // reserved for future Aave extensions (e.g., permit, isolation mode flags)

        AdapterConfig memory cfg = _decode(adapterConfig);
        _checkRateMode(cfg.interestRateMode);

        target = cfg.pool;
        value = 0;

        if (action == Action.Supply) {
            approvalToken = asset;
            approvalSpender = cfg.pool;
            data = abi.encodeWithSelector(IAaveV3Pool.supply.selector, asset, amount, account, cfg.referralCode);
            return (target, value, data, approvalToken, approvalSpender);
        }

        if (action == Action.Withdraw) {
            approvalToken = address(0);
            approvalSpender = address(0);
            data = abi.encodeWithSelector(IAaveV3Pool.withdraw.selector, asset, amount, account);
            return (target, value, data, approvalToken, approvalSpender);
        }

        if (action == Action.Borrow) {
            approvalToken = address(0);
            approvalSpender = address(0);
            data = abi.encodeWithSelector(
                IAaveV3Pool.borrow.selector, asset, amount, uint256(cfg.interestRateMode), cfg.referralCode, account
            );
            return (target, value, data, approvalToken, approvalSpender);
        }

        if (action == Action.Repay) {
            approvalToken = asset;
            approvalSpender = cfg.pool;
            data = abi.encodeWithSelector(
                IAaveV3Pool.repay.selector, asset, amount, uint256(cfg.interestRateMode), account
            );
            return (target, value, data, approvalToken, approvalSpender);
        }

        // unreachable for enum, but keeps this adapter robust against future changes
        revert InvalidAction();
    }

    function healthFactor(address account, bytes calldata adapterConfig) external view returns (uint256) {
        AdapterConfig memory cfg = _decode(adapterConfig);
        (,,,,, uint256 hf) = IAaveV3Pool(cfg.pool).getUserAccountData(account);
        return hf;
    }

    function _decode(bytes calldata adapterConfig) internal pure returns (AdapterConfig memory cfg) {
        if (adapterConfig.length == 0) revert InvalidAdapterConfig();
        cfg = abi.decode(adapterConfig, (AdapterConfig));
        if (cfg.pool == address(0)) revert InvalidAdapterConfig();
    }

    function _checkRateMode(uint8 rateMode) internal pure {
        // Aave: 1 = stable, 2 = variable. (Some markets may disable stable, but the pool will revert.)
        if (rateMode != 1 && rateMode != 2) revert InvalidRateMode(rateMode);
    }
}

