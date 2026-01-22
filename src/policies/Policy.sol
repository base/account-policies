// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../PolicyManager.sol";

/// @notice A policy defines authorization semantics and returns a wallet call plan.
abstract contract Policy {
    address public constant NATIVE_TOKEN = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    PolicyManager public immutable POLICY_MANAGER;

    error InvalidSender(address sender, address expected);

    constructor(address policyManager) {
        POLICY_MANAGER = PolicyManager(policyManager);
    }

    modifier onlyPolicyManager() {
        _requireSender(address(POLICY_MANAGER));
        _;
    }

    /// @notice Policy hook invoked during installation.
    /// @dev MUST revert if the policy refuses the installation.
    ///
    /// `policyId` is the EIP-712 struct hash of `binding` as computed by `PolicyManager`.
    /// `policyConfig` is the full config preimage bytes that match `binding.policyConfigHash`.
    function onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller) external virtual;

    /// @notice Policy hook invoked during revocation.
    /// @dev Called by `PolicyManager` after the binding has been marked revoked.
    function onRevoke(bytes32 policyId, address account, address caller) external virtual;

    /// @notice Authorize the execution and build the account call and optional post-call (executed on the policy).
    /// @dev MUST revert on unauthorized execution.
    ///
    /// `caller` is the external caller of `PolicyManager.execute`.
    function onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) external virtual returns (bytes memory accountCallData, bytes memory postCallData);

    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }
}

