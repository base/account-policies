// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Policy} from "./Policy.sol";

/// @notice Policy that allows an executor to execute a constrained ERC20->(something) swap on a fixed
/// `swapTarget`, bounded by `maxAmountIn` and checked by a prorated minimum receive amount.
/// @dev Proration is based on the configured minimum receive amount for `maxAmountIn`:
///      proratedMinOut = floor(minAmountOutForMaxAmountIn * amountIn / maxAmountIn).
///      Wallet call plan:
///      - approve `swapTarget` for `amountIn`
///      - call `swapTarget` with `swapData`
///      - reset approval to 0
///      Post-call verifies tokenOut balance delta >= proratedMinOut.
contract SwapPolicy is Policy {
    error InvalidPolicyData();
    error InvalidPolicyConfigAccount(address actual, address expected);
    error SelectorMismatch(bytes4 actual, bytes4 expected);
    error AmountInTooHigh(uint256 amountIn, uint256 maxAmountIn);
    error ZeroMaxAmountIn();
    error TokenOutBalanceTooLow(uint256 initialBalance, uint256 finalBalance, uint256 minAmountOut);
    error Unauthorized(address caller);
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    mapping(bytes32 policyId => bytes32 configHash) internal _configHashes;

    struct Config {
        address account;
        address executor;
        address tokenIn;
        address tokenOut;
        address swapTarget;
        bytes4 swapSelector;

        /// @dev Maximum allowed `amountIn` per execution (also used as the proration denominator).
        uint256 maxAmountIn;
        /// @dev Minimum amount of tokenOut required when `amountIn == maxAmountIn`.
        uint256 minAmountOutForMaxAmountIn;
    }

    struct PolicyData {
        uint256 amountIn;
        bytes swapData;
    }

    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        internal
        override
    {
        caller;
        // Store the authorized config hash so execution can validate config preimages without manager storage.
        _configHashes[policyId] = keccak256(policyConfig);

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.account != account) revert InvalidPolicyConfigAccount(cfg.account, account);
        if (cfg.maxAmountIn == 0) revert ZeroMaxAmountIn();
    }

    function _onUninstall(bytes32 policyId, address account, address caller) internal override {
        if (caller != account) revert InvalidSender(caller, account);
        delete _configHashes[policyId];
    }

    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        bytes32 expected = _configHashes[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);

        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.account != account) revert InvalidPolicyConfigAccount(cfg.account, account);
        if (cfg.maxAmountIn == 0) revert ZeroMaxAmountIn();
        if (caller != cfg.executor) revert Unauthorized(caller);

        PolicyData memory data = abi.decode(policyData, (PolicyData));
        if (data.swapData.length < 4) revert InvalidPolicyData();
        if (data.amountIn > cfg.maxAmountIn) revert AmountInTooHigh(data.amountIn, cfg.maxAmountIn);

        // Read the first 4 bytes of calldata and compare to the expected selector.
        bytes4 actualSelector = bytes4(bytes32(data.swapData));
        if (actualSelector != cfg.swapSelector) revert SelectorMismatch(actualSelector, cfg.swapSelector);

        // Snapshot tokenOut balance before wallet execution.
        uint256 initialOutBalance = IERC20(cfg.tokenOut).balanceOf(cfg.account);

        // Prorate minAmountOut based on amountIn.
        uint256 proratedMinAmountOut = Math.mulDiv(cfg.minAmountOutForMaxAmountIn, data.amountIn, cfg.maxAmountIn);

        // Wallet call plan: approve -> swap -> approve(0)
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
        calls[0] = CoinbaseSmartWallet.Call({
            target: cfg.tokenIn,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, cfg.swapTarget, data.amountIn)
        });
        calls[1] = CoinbaseSmartWallet.Call({target: cfg.swapTarget, value: 0, data: data.swapData});
        calls[2] = CoinbaseSmartWallet.Call({
            target: cfg.tokenIn, value: 0, data: abi.encodeWithSelector(IERC20.approve.selector, cfg.swapTarget, 0)
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = abi.encodeWithSelector(
            this.afterExecute.selector, cfg.account, cfg.tokenOut, initialOutBalance, proratedMinAmountOut
        );
    }

    function afterExecute(address account, address tokenOut, uint256 initialOutBalance, uint256 minAmountOut)
        external
        view
        onlyPolicyManager
    {
        uint256 finalOutBalance = IERC20(tokenOut).balanceOf(account);
        if (finalOutBalance < initialOutBalance + minAmountOut) {
            revert TokenOutBalanceTooLow(initialOutBalance, finalOutBalance, minAmountOut);
        }
    }
}

