// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Policy} from "../../../src/policies/Policy.sol";

/// @title InstallTestPolicy
///
/// @notice Test-only policy that records install hook parameters and can be configured to revert.
///
/// @dev Intended for `PolicyManager.install*` tests.
contract InstallTestPolicy is Policy {
    /// @notice Thrown when configured to revert on install.
    error OnInstallReverted();

    bytes32 public lastPolicyId;
    address public lastAccount;
    bytes public lastPolicyConfig;
    address public lastEffectiveCaller;

    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address effectiveCaller)
        internal
        override
    {
        lastPolicyId = policyId;
        lastAccount = account;
        lastPolicyConfig = policyConfig;
        lastEffectiveCaller = effectiveCaller;

        // Sentinel: any config whose first byte is 0xff triggers a revert for revert-bubbling tests.
        if (policyConfig.length > 0 && policyConfig[0] == 0xff) revert OnInstallReverted();
    }

    function _onUninstall(bytes32, address, bytes calldata, bytes calldata, address) internal override {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (bytes memory, bytes memory)
    {
        return ("", "");
    }
}

