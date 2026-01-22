// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Policy} from "./Policy.sol";

/// @notice Allow executors to send any tokens from account to allowed recipients per-user.
contract AllowlistedSendPolicy is Policy {
    mapping(bytes32 policyId => address executor) public executors;
    mapping(address account => mapping(address recipient => bool allowed)) public isRecipientAllowed;

    event AllowlistUpdated(address indexed account, address indexed recipient, bool allowed);

    constructor(address policyManager) Policy(policyManager) {}

    // To approve policy, batch calls from account this contract to update recipient allowlist and PolicyManager to approve executor.
    function updateAllowlist(address recipient, bool allowed) external {
        isRecipientAllowed[msg.sender][recipient] = allowed;
        emit AllowlistUpdated(msg.sender, recipient, allowed);
    }

    function onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        external
        override
        onlyPolicyManager
    {
        address executor = abi.decode(policyConfig, (address));
        executors[policyId] = executor;
    }

    function onRevoke(bytes32 policyId, address account, address caller) external override onlyPolicyManager {
        if (caller != account) revert InvalidSender(caller, account);
        delete executors[policyId];
    }

    function onExecute(
        bytes32 policyId,
        address account,
        bytes calldata, // policyConfig
        bytes calldata executeParams,
        address caller
    ) external override onlyPolicyManager returns (bytes memory accountCallData, bytes memory postCallData) {
        if (caller != executors[policyId]) revert InvalidSender(caller, executors[policyId]);

        (uint256 amount, address token, address recipient) = abi.decode(executeParams, (uint256, address, address));
        if (amount == 0) revert ZeroAmount();
        if (token == address(0)) revert ZeroToken();
        if (!isRecipientAllowed[account][recipient]) revert Unauthorized(recipient);

        address target;
        uint256 value;
        bytes memory data;
        if (token == NATIVE_TOKEN) {
            target = recipient;
            value = amount;
        } else {
            target = token;
            data = abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount);
        }
        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, target, value, data);
    }
}
