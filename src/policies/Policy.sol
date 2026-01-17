// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyTypes} from "../PolicyTypes.sol";

/// @notice A policy defines authorization semantics and returns a wallet call plan.
interface Policy {
    /// @notice Validate whether an execution is authorized.
    /// @dev MUST revert on unauthorized execution.
    ///
    /// `caller` is the external caller of `PolicyManager.execute`.
    /// `authorizationData` is an opaque blob forwarded from `PolicyManager.execute` (e.g. a signature).
    /// `execDigest` is the EIP-712 digest computed by `PolicyManager` for this execution.
    function authorize(
        PolicyTypes.Install calldata install,
        uint256 execNonce,
        bytes calldata policyConfig,
        bytes calldata policyData,
        bytes32 execDigest,
        address caller,
        bytes calldata authorizationData
    ) external;

    /// @notice Build the account call and optional post-call (executed on the policy).
    function onExecute(
        PolicyTypes.Install calldata install,
        uint256 execNonce,
        bytes calldata policyConfig,
        bytes calldata policyData
    ) external returns (bytes memory accountCallData, bytes memory postCallData);
}


