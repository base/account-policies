// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CallForwardingPolicy} from "./CallForwardingPolicy.sol";

/// @title RecordingReplacePolicy
///
/// @notice Test-only policy that records whether replacement-aware hooks were called.
///
/// @dev Used to assert that `PolicyManager.replace*` calls `onReplace` for both the old and new policy instances.
contract RecordingReplacePolicy is CallForwardingPolicy {
    bool public oldPolicyCalled;
    bool public newPolicyCalled;

    constructor(address policyManager) CallForwardingPolicy(policyManager) {}

    function _onUninstallForReplace(bytes32, address, bytes calldata, bytes calldata, address, bytes32, address)
        internal
        override
    {
        oldPolicyCalled = true;
    }

    function _onInstallForReplace(bytes32, address, bytes calldata, bytes calldata, address, bytes32, address)
        internal
        override
    {
        newPolicyCalled = true;
    }
}

