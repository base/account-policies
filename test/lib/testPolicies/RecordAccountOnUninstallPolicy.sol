// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Policy} from "../../../src/policies/Policy.sol";

/// @title RecordAccountOnUninstallPolicy
///
/// @notice Test-only policy that records the `account` forwarded to `onUninstall`.
///
/// @dev Used to verify that `PolicyManager` forwards the stored record account (not user-supplied binding fields)
///      when uninstalling an installed instance via binding-mode.
contract RecordAccountOnUninstallPolicy is Policy {
    address public lastUninstallAccount;

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

    function _onUninstall(bytes32, address account, bytes calldata, bytes calldata, address) internal override {
        lastUninstallAccount = account;
    }
}

