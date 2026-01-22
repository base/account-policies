// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Policy} from "./Policy.sol";
import {PolicyManager} from "../PolicyManager.sol";

/// @notice Morpho vault deposit policy.
/// @dev Intentionally conservative: fixed vault, fixed receiver (the account), bounded amount, approval reset,
///      and optional cumulative cap.
contract AllowlistedSendPolicy is Policy {
    struct Config {
        address executor;
        address[] initialRecipients;
    }

    struct ExecuteParams {
        address recipient;
        address token;
        uint256 amount;
    }

    mapping(bytes32 policyId => address executor) public executors;
    mapping(bytes32 policyId => mapping(address recipient => bool allowed)) public isRecipientAllowed;

    event AllowlistUpdated(bytes32 indexed policyId, address indexed account, address indexed recipient, bool allowed);

    constructor(address policyManager) Policy(policyManager) {}

    function updateAllowlist(bytes32 policyId, address recipient, bool allowed) external {
        address account = POLICY_MANAGER.getAccountForPolicy(address(this), policyId);
        _requireSender(account);

        isRecipientAllowed[policyId][recipient] = allowed;
        emit AllowlistUpdated(policyId, account, recipient, allowed);
    }

    function onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        external
        override
        onlyPolicyManager
    {
        if (caller != account) revert InvalidSender(caller, account);
        Config memory cfg = abi.decode(policyConfig, (Config));
        executors[policyId] = cfg.executor;
        for (uint256 i = 0; i < cfg.initialRecipients.length; i++) {
            isRecipientAllowed[policyId][cfg.initialRecipients[i]] = true;
            emit AllowlistUpdated(policyId, account, cfg.initialRecipients[i], true);
        }
    }

    function onRevoke(bytes32 policyId, address account, address caller) external override onlyPolicyManager {
        if (caller != account) revert InvalidSender(caller, account);
        delete executors[policyId];
    }

    function onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata executeParams,
        address caller
    ) external override onlyPolicyManager returns (bytes memory accountCallData, bytes memory postCallData) {
        if (caller != executors[policyId]) revert InvalidSender(caller, executors[policyId]);

        ExecuteParams memory params = abi.decode(executeParams, (ExecuteParams));
        if (params.token == address(0)) revert ZeroToken();
        if (params.amount == 0) revert ZeroAmount();
        if (!isRecipientAllowed[policyId][params.recipient]) revert Unauthorized(caller);

        address target;
        address value;
        bytes memory data;
        if (params.token == NATIVE_TOKEN) {
            target = params.recipient;
            value = params.amount;
        } else {
            target = params.token;
            data = abi.encodeWithSelector(IERC20.transfer.selector, params.recipient, params.amount);
        }
        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, data);
    }
}
