// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallForwardingPolicy} from "./CallForwardingPolicy.sol";

/// @title RevertOnUninstallForReplacePolicy
///
/// @notice Test-only policy that reverts during the replacement-aware uninstall hook.
///
/// @dev Used to assert the account escape hatch during replacement uninstalls.
contract RevertOnUninstallForReplacePolicy is CallForwardingPolicy {
    /// @notice Thrown on replacement-aware uninstall.
    error OnUninstallReverted();

    constructor(address policyManager) CallForwardingPolicy(policyManager) {}

    function _onUninstallForReplace(bytes32, address, bytes calldata, bytes calldata, address, bytes32, address)
        internal
        pure
        override
    {
        revert OnUninstallReverted();
    }
}

