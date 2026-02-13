// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Policy} from "../../../src/policies/Policy.sol";

/// @title CallForwardingPolicy
///
/// @notice Test-only policy that forwards an arbitrary call through an account's `execute` entrypoint.
///         Intended for verifying `PolicyManager` execution plumbing (manager -> policy -> manager -> account).
contract CallForwardingPolicy is Policy {
    enum PostAction {
        None,
        CallPost,
        RevertPost
    }

    struct ForwardCall {
        address target;
        uint256 value;
        bytes data;
        bool revertOnExecute;
        PostAction postAction;
    }

    error OnExecuteReverted();
    error PostCallReverted(bytes32 policyId);

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

        if (f.revertOnExecute) revert OnExecuteReverted();

        lastExecutedPolicyId = policyId;
        lastAccount = account;
        lastManagerCaller = caller;
        lastForwardHash = keccak256(abi.encode(f.target, f.value, keccak256(f.data)));

        accountCallData = abi.encodeWithSignature("execute(address,uint256,bytes)", f.target, f.value, f.data);
        if (f.postAction == PostAction.CallPost) {
            postCallData = abi.encodeWithSelector(this.post.selector, policyId);
        } else if (f.postAction == PostAction.RevertPost) {
            postCallData = abi.encodeWithSelector(this.postRevert.selector, policyId);
        }
    }

    function post(bytes32 policyId) external {
        _requireSender(address(POLICY_MANAGER));
        postCalls++;
        lastExecutedPolicyId = policyId;
    }

    function postRevert(bytes32 policyId) external view {
        _requireSender(address(POLICY_MANAGER));
        revert PostCallReverted(policyId);
    }
}

