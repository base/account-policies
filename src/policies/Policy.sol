// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyTypes} from "../PolicyTypes.sol";

/// @notice A policy defines authorization semantics and returns a wallet call plan.
interface Policy {
    /// @notice Authorize the execution and build the account call and optional post-call (executed on the policy).
    /// @dev MUST revert on unauthorized execution.
    ///
    /// `caller` is the external caller of `PolicyManager.execute`.
    function onExecute(
        PolicyTypes.PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) external returns (bytes memory accountCallData, bytes memory postCallData);
}

