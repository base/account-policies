// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallForwardingPolicy} from "./CallForwardingPolicy.sol";

/// @title RevertOnReplacePolicy
///
/// @notice Test-only policy that reverts during the replacement-aware install hook.
///
/// @dev Used to assert that `PolicyManager.replace*` bubbles reverts from the new policy's install-for-replace path.
contract RevertOnReplacePolicy is CallForwardingPolicy {
    /// @notice Thrown on replacement-aware install.
    error OnReplaceReverted();

    constructor(address policyManager) CallForwardingPolicy(policyManager) {}

    function _onInstallForReplace(bytes32, address, bytes calldata, bytes calldata, address, bytes32, address)
        internal
        pure
        override
    {
        revert OnReplaceReverted();
    }
}

