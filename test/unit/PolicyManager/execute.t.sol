// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";
import {CallForwardingPolicy} from "../../lib/testPolicies/CallForwardingPolicy.sol";
import {RevertingReceiver} from "../../lib/mocks/RevertingReceiver.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `PolicyManager.execute`.
contract ExecuteTest is PolicyManagerTestBase {
    /// @dev Maximum length for fuzzed `bytes` inputs (calldata) to keep fuzz runs fast.
    uint256 internal constant MAX_BYTES_LEN = 256;
    /// @dev Maximum ETH value forwarded through the wallet call.
    uint256 internal constant MAX_CALL_VALUE = 1 ether;

    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Asserts that `execute` reverts with `BeforeValidAfter` for the current timestamp.
    ///
    /// @param policyId Installed policy identifier being executed.
    /// @param validAfter The binding lower-bound timestamp (seconds) stored in the policy record.
    /// @param policyConfig Opaque config bytes forwarded to the policy.
    /// @param executionData Opaque execution bytes forwarded to the policy.
    function _expectRevertBeforeValidAfter(
        bytes32 policyId,
        uint40 validAfter,
        bytes calldata policyConfig,
        bytes calldata executionData
    ) internal {
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.BeforeValidAfter.selector, uint40(block.timestamp), validAfter)
        );
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);
    }

    /// @notice Asserts that `execute` reverts with `AfterValidUntil` for the current timestamp.
    ///
    /// @param policyId Installed policy identifier being executed.
    /// @param validUntil The binding upper-bound timestamp (seconds) stored in the policy record.
    /// @param policyConfig Opaque config bytes forwarded to the policy.
    /// @param executionData Opaque execution bytes forwarded to the policy.
    function _expectRevertAfterValidUntil(
        bytes32 policyId,
        uint40 validUntil,
        bytes calldata policyConfig,
        bytes calldata executionData
    ) internal {
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.AfterValidUntil.selector, uint40(block.timestamp), validUntil)
        );
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);
    }

    /// @notice Installs `callPolicy` for `account` using the given config + binding parameters.
    ///
    /// @dev The manager call is authorized via `vm.prank(account)`.
    ///
    /// @param installPolicyConfig Policy config bytes used for installation (hashed into the binding).
    /// @param salt Salt used to derive a distinct `policyId`.
    /// @param validAfter Lower-bound timestamp (seconds) for the binding.
    /// @param validUntil Upper-bound timestamp (seconds) for the binding.
    ///
    /// @return policyId Deterministic binding identifier derived from the provided binding inputs.
    /// @return policyConfig The same config bytes passed to install (returned for convenience).
    function _installCallPolicy(bytes memory installPolicyConfig, uint256 salt, uint40 validAfter, uint40 validUntil)
        internal
        returns (bytes32 policyId, bytes memory policyConfig)
    {
        policyConfig = installPolicyConfig;
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(callPolicy),
            validAfter: validAfter,
            validUntil: validUntil,
            salt: salt,
            policyConfigHash: keccak256(policyConfig)
        });

        vm.prank(address(account));
        policyId = policyManager.install(binding, policyConfig);
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policyId is not installed.
    ///
    /// @dev Expects `PolicyManager.PolicyNotInstalled`.
    ///
    /// @param policy Policy address passed to `PolicyManager.execute`.
    /// @param policyId Policy identifier expected to be missing.
    /// @param policyConfig Opaque config bytes forwarded to the policy (unused in this revert path).
    /// @param executionData Opaque execution bytes forwarded to the policy (unused in this revert path).
    function test_reverts_whenPolicyNotInstalled(
        address policy,
        bytes32 policyId,
        bytes calldata policyConfig,
        bytes calldata executionData
    ) public {
        vm.assume(policyConfig.length <= MAX_BYTES_LEN);
        vm.assume(executionData.length <= MAX_BYTES_LEN);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyNotInstalled.selector, policyId));
        policyManager.execute(policy, policyId, policyConfig, executionData);
    }

    /// @notice Reverts when the policyId is uninstalled (permanently disabled).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param uninstallData Opaque policy-defined uninstall authorization payload.
    /// @param executePolicyConfig Opaque config bytes forwarded to the policy during `execute` (unused in this revert path).
    /// @param executionData Opaque execution bytes forwarded to the policy during `execute` (unused in this revert path).
    function test_reverts_whenPolicyIsDisabled(
        bytes32 configSeed,
        uint256 salt,
        bytes calldata uninstallData,
        bytes calldata executePolicyConfig,
        bytes calldata executionData
    ) public {
        vm.assume(uninstallData.length <= MAX_BYTES_LEN);
        vm.assume(executePolicyConfig.length <= MAX_BYTES_LEN);
        vm.assume(executionData.length <= MAX_BYTES_LEN);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        PolicyManager.PolicyBinding memory emptyBinding;
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: emptyBinding,
            policy: address(callPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: uninstallData
        });
        policyManager.uninstall(payload);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, policyId));
        policyManager.execute(address(callPolicy), policyId, executePolicyConfig, executionData);
    }

    /// @notice Reverts when current timestamp is before `validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    ///
    /// @param validAfter Binding lower bound (seconds). Zero means "no lower bound" and is excluded by bounding.
    /// @param beforeOffset Seed used to pick a timestamp strictly before `validAfter`.
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param policyConfig Opaque config bytes forwarded to the policy during `execute`.
    /// @param executionData Opaque execution bytes forwarded to the policy during `execute`.
    function test_reverts_whenBeforeValidAfter(
        uint40 validAfter,
        uint40 beforeOffset,
        bytes32 configSeed,
        uint256 salt,
        bytes calldata policyConfig,
        bytes calldata executionData
    ) public {
        vm.assume(policyConfig.length <= MAX_BYTES_LEN);
        vm.assume(executionData.length <= MAX_BYTES_LEN);

        validAfter = uint40(bound(uint256(validAfter), 1, uint256(type(uint40).max)));

        vm.warp(uint256(validAfter));
        (bytes32 policyId,) = _installCallPolicy(abi.encode(configSeed), salt, validAfter, 0);

        // Choose any timestamp strictly before `validAfter` without discarding fuzz cases.
        uint40 nowTs = uint40(uint256(beforeOffset) % uint256(validAfter));
        vm.warp(uint256(nowTs));
        _expectRevertBeforeValidAfter(policyId, validAfter, policyConfig, executionData);
    }

    /// @notice Reverts when current timestamp is at/after `validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    ///
    /// @param validUntil Binding upper bound (seconds). Zero means "no upper bound" and is excluded by bounding.
    /// @param afterOffset Seed used to pick a timestamp at/after `validUntil`.
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param policyConfig Opaque config bytes forwarded to the policy during `execute`.
    /// @param executionData Opaque execution bytes forwarded to the policy during `execute`.
    function test_reverts_whenAfterValidUntil(
        uint40 validUntil,
        uint40 afterOffset,
        bytes32 configSeed,
        uint256 salt,
        bytes calldata policyConfig,
        bytes calldata executionData
    ) public {
        vm.assume(policyConfig.length <= MAX_BYTES_LEN);
        vm.assume(executionData.length <= MAX_BYTES_LEN);

        vm.warp(1_000_000);
        uint40 nowTs = uint40(block.timestamp);
        validUntil = uint40(bound(uint256(validUntil), uint256(nowTs) + 1, uint256(type(uint40).max)));

        (bytes32 policyId,) = _installCallPolicy(abi.encode(configSeed), salt, 0, validUntil);

        // Choose any timestamp at/after `validUntil` without discarding fuzz cases.
        uint40 range = type(uint40).max - validUntil + 1;
        uint40 atOrAfter = validUntil + uint40(uint256(afterOffset) % uint256(range));
        vm.warp(uint256(atOrAfter));
        _expectRevertAfterValidUntil(policyId, validUntil, policyConfig, executionData);
    }

    /// @notice Bubbles a revert when the policy's `onExecute` hook reverts.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data (unused in this revert path).
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_reverts_whenPolicyOnExecuteReverts(bytes32 configSeed, uint256 salt, bytes32 tag, uint256 value)
        public
    {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: value,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: true,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(abi.encodeWithSelector(CallForwardingPolicy.OnExecuteReverted.selector));
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);
    }

    /// @notice Bubbles a revert when the account call fails.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_reverts_whenAccountCallReverts(bytes32 configSeed, uint256 salt, bytes32 tag, uint256 value) public {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        RevertingReceiver revertingReceiver = new RevertingReceiver();
        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(revertingReceiver),
            value: value,
            data: abi.encodeWithSelector(revertingReceiver.ping.selector),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(abi.encodeWithSelector(RevertingReceiver.ReceiverReverted.selector));
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);
    }

    /// @notice Bubbles a revert when the post-call fails.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_reverts_whenPostCallReverts(bytes32 configSeed, uint256 salt, bytes32 tag, uint256 value) public {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: value,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.RevertPost
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(abi.encodeWithSelector(CallForwardingPolicy.PostCallReverted.selector, policyId));
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyExecuted` on successful execution.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_emitsPolicyExecuted(bytes32 configSeed, uint256 salt, bytes32 tag, uint256 value) public {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: value,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyExecuted(policyId, address(account), address(callPolicy), keccak256(executionData));
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);
    }

    /// @notice Calls the policy hook with the immediate manager caller as `caller`.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param relayer Relayer address used as `msg.sender` for the manager call.
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_callsPolicyOnExecute_withImmediateCaller(
        bytes32 configSeed,
        uint256 salt,
        address relayer,
        bytes32 tag,
        uint256 value
    ) public {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        vm.assume(relayer != address(0));
        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: value,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.prank(relayer);
        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);

        assertEq(callPolicy.lastExecutedPolicyId(), policyId);
        assertEq(callPolicy.lastAccount(), address(account));
        assertEq(callPolicy.lastManagerCaller(), relayer);
    }

    /// @notice Executes account call data returned by the policy.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_callsAccount_withPolicyPreparedCallData(bytes32 configSeed, uint256 salt, bytes32 tag, uint256 value)
        public
    {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: value,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);

        assertEq(receiver.calls(), 1);
        assertEq(receiver.lastTag(), tag);
        assertEq(receiver.lastCaller(), address(account));
    }

    /// @notice Executes post-call data returned by the policy after calling the account.
    ///
    /// @param configSeed Seed used to build the installed policy config (hashed into `policyId`).
    /// @param salt Salt used to build the binding (hashed into `policyId`).
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    /// @param value ETH value forwarded to the receiver call (bounded in-test).
    function test_callsPolicyPostCall_afterAccountCall(bytes32 configSeed, uint256 salt, bytes32 tag, uint256 value)
        public
    {
        value = bound(value, 0, MAX_CALL_VALUE);
        vm.deal(address(account), value);

        (bytes32 policyId, bytes memory policyConfig) = _installCallPolicy(abi.encode(configSeed), salt, 0, 0);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: value,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.CallPost
        });
        bytes memory executionData = abi.encode(f);

        policyManager.execute(address(callPolicy), policyId, policyConfig, executionData);

        assertEq(receiver.calls(), 1);
        assertEq(receiver.lastTag(), tag);
        assertEq(callPolicy.postCalls(), 1);
        assertEq(callPolicy.lastExecutedPolicyId(), policyId);
    }
}

