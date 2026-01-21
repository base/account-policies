// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {PolicyTypes} from "../PolicyTypes.sol";
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
    error InvalidSender(address sender, address expected);
    error Unauthorized(address caller);
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    address public immutable POLICY_MANAGER;

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
        view
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
        requireSender(POLICY_MANAGER)
    {
        uint256 finalOutBalance = IERC20(tokenOut).balanceOf(account);
        if (finalOutBalance < initialOutBalance + minAmountOut) {
            revert TokenOutBalanceTooLow(initialOutBalance, finalOutBalance, minAmountOut);
        }
    }
}

