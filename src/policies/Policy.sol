// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyTypes} from "../PolicyTypes.sol";

/// @notice A policy defines authorization semantics and returns a wallet call plan.
interface Policy {
    /// @notice Policy hook invoked during installation.
    /// @dev MUST revert if the policy refuses the installation.
    ///
    /// `policyId` is the EIP-712 struct hash of `binding` as computed by `PolicyManager`.
    /// `policyConfig` is the full config preimage bytes that match `binding.policyConfigHash`.
    function onInstall(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId, bytes calldata policyConfig)
        external;

    /// @notice Policy hook invoked during revocation.
    /// @dev Called by `PolicyManager` after the binding has been marked revoked.
    function onRevoke(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId) external;

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

