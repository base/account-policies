// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Policy} from "../../../src/policies/Policy.sol";

/// @title RevertOnUninstallPolicy
///
/// @notice Test-only policy that always reverts during `onUninstall`.
///
/// @dev Used to test `PolicyManager.Unauthorized` behavior and the account escape hatch during uninstall.
contract RevertOnUninstallPolicy is Policy {
    /// @notice Thrown on every uninstall attempt.
    error OnUninstallReverted();

    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32, address, bytes calldata, address) internal override {}

    function _onExecute(bytes32, address, bytes calldata, bytes calldata, address)
        internal
        pure
        override
        returns (bytes memory, bytes memory)
    {
        return ("", "");
    }

    function _onUninstall(bytes32, address, bytes calldata, bytes calldata, address) internal pure override {
        revert OnUninstallReverted();
    }
}

