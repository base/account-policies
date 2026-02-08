// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Policy} from "../../../src/policies/Policy.sol";

/// @title CallForwardingPolicy
///
/// @notice Test-only policy that forwards an arbitrary call through an account's `execute` entrypoint.
///         Intended for verifying `PolicyManager` execution plumbing (manager -> policy -> account).
contract CallForwardingPolicy is Policy {
    struct ForwardCall {
        address target;
        uint256 value;
        bytes data;
        bool doPost;
    }

    bytes32 public lastExecutedPolicyId;
    address public lastAccount;
    address public lastManagerCaller;
    bytes32 public lastForwardHash;
    uint256 public postCalls;

    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32, address, bytes calldata, address) internal override {}

    function _onUninstall(bytes32, address, bytes calldata, bytes calldata, address) internal override {}

    function _onExecute(bytes32 policyId, address account, bytes calldata, bytes calldata executionData, address caller)
        internal
        override
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        ForwardCall memory f = abi.decode(executionData, (ForwardCall));

        lastExecutedPolicyId = policyId;
        lastAccount = account;
        lastManagerCaller = caller;
        lastForwardHash = keccak256(abi.encode(f.target, f.value, keccak256(f.data)));

        accountCallData = abi.encodeWithSignature("execute(address,uint256,bytes)", f.target, f.value, f.data);
        if (f.doPost) {
            postCallData = abi.encodeWithSelector(this.post.selector, policyId);
        }
    }

    function post(bytes32 policyId) external {
        _requireSender(address(POLICY_MANAGER));
        postCalls++;
        lastExecutedPolicyId = policyId;
    }
}

