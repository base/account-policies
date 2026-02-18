// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";
import {CallForwardingPolicy} from "../../lib/testPolicies/CallForwardingPolicy.sol";
import {InstallTestPolicy} from "../../lib/testPolicies/InstallTestPolicy.sol";
import {RevertingReceiver} from "../../lib/mocks/RevertingReceiver.sol";

/// @title InstallWithSignatureTest
///
/// @notice Test contract for `PolicyManager.installWithSignature`.
contract InstallWithSignatureTest is PolicyManagerTestBase {
    /// @dev Maximum length for fuzzed `bytes` inputs to keep fuzz runs fast.
    uint256 internal constant MAX_BYTES_LEN = 256;
    /// @dev Base timestamp used for warp-based tests.
    uint40 internal constant WARP_BASE_TIMESTAMP = 1_000_000;
    /// @dev Config seed used when a single canonical config is needed.
    uint256 internal constant DEFAULT_CONFIG_SEED = 1;

    InstallTestPolicy internal installPolicy;

    function setUp() public {
        setUpPolicyManagerBase();
        installPolicy = new InstallTestPolicy(address(policyManager));
        vm.label(address(installPolicy), "InstallTestPolicy");
    }

    /// @notice Returns a config seed that does not trigger InstallTestPolicy's revert sentinel.
    function _safeConfigSeed(bytes32 configSeed) internal pure returns (bytes32) {
        bytes32 mask = bytes32(uint256(0xff) << 248);
        if ((configSeed & mask) == mask) {
            return configSeed ^ mask;
        }
        return configSeed;
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policy address has no deployed code.
    ///
    /// @dev Expects `PolicyManager.PolicyNotContract`. Signature is valid but the policy address is an EOA.
    ///
    /// @param policy Fuzzed address with no code.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenPolicyNotContract(address policy, uint256 salt) public {
        vm.assume(policy != address(0));
        vm.assume(policy.code.length == 0);

        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: policy,
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfig: policyConfig
        });
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyNotContract.selector, policy));
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Reverts when the account signature is invalid.
    ///
    /// @dev Expects `PolicyManager.InvalidSignature`.
    ///
    /// @param userSig Arbitrary invalid signature bytes (length bounded to keep fuzz fast).
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenInvalidSignature(bytes memory userSig, bytes32 configSeed, uint256 salt) public {
        vm.assume(userSig.length <= MAX_BYTES_LEN);

        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        vm.expectRevert(PolicyManager.InvalidSignature.selector);
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Reverts when the policyId has been uninstalled (permanently disabled).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenPolicyIsDisabled() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        vm.prank(address(account));
        bytes32 policyId = policyManager.install(binding);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), validAfter: 0, validUntil: 0, salt: 0, policyConfig: bytes("")
            }),
            policy: address(installPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });
        vm.prank(address(account));
        policyManager.uninstall(payload);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, policyId));
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Reverts when current timestamp is before `binding.validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    ///
    /// @param validAfterSeed Seed used to derive a future validAfter bound.
    /// @param beforeOffset Seed used to pick a timestamp strictly before validAfter.
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenBeforeValidAfter(
        uint40 validAfterSeed,
        uint40 beforeOffset,
        bytes32 configSeed,
        uint256 salt
    ) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint40 nowTs = uint40(block.timestamp);
        uint40 validAfter = uint40(bound(uint256(validAfterSeed), uint256(nowTs) + 1, uint256(type(uint40).max)));

        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        binding.validAfter = validAfter;
        binding.validUntil = 0;

        uint40 range = validAfter;
        uint40 beforeTs = uint40(uint256(beforeOffset) % uint256(range));
        vm.warp(uint256(beforeTs));

        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.BeforeValidAfter.selector, beforeTs, validAfter));
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Reverts when current timestamp is at/after `binding.validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    ///
    /// @param validUntilSeed Seed used to derive a past validUntil bound.
    /// @param afterOffset Seed used to pick a timestamp at/after validUntil.
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_reverts_whenAfterValidUntil(
        uint40 validUntilSeed,
        uint40 afterOffset,
        bytes32 configSeed,
        uint256 salt
    ) public {
        vm.warp(WARP_BASE_TIMESTAMP);
        uint40 nowTs = uint40(block.timestamp);
        uint40 validUntil = uint40(bound(uint256(validUntilSeed), 1, uint256(nowTs)));

        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        binding.validAfter = 0;
        binding.validUntil = validUntil;

        uint40 range = type(uint40).max - validUntil + 1;
        uint40 atOrAfter = validUntil + uint40(uint256(afterOffset) % uint256(range));
        vm.warp(uint256(atOrAfter));

        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.AfterValidUntil.selector, atOrAfter, validUntil));
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Bubbles a revert when the policy's `onInstall` hook reverts.
    function test_reverts_whenPolicyOnInstallReverts() public {
        bytes memory policyConfig = hex"ff";
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(InstallTestPolicy.OnInstallReverted.selector);
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Bubbles a revert when the policy's `onExecute` hook reverts (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andPolicyOnExecuteReverts() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: true,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(CallForwardingPolicy.OnExecuteReverted.selector);
        policyManager.installWithSignature(binding, userSig, executionData);
    }

    /// @notice Bubbles a revert when the account call fails (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andAccountCallReverts() public {
        RevertingReceiver revertingReceiver = new RevertingReceiver();

        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(revertingReceiver),
            value: 0,
            data: abi.encodeWithSelector(revertingReceiver.ping.selector),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(RevertingReceiver.ReceiverReverted.selector);
        policyManager.installWithSignature(binding, userSig, executionData);
    }

    /// @notice Bubbles a revert when the post-call fails (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andPostCallReverts() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        bytes32 policyId = policyManager.getPolicyId(binding);
        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.RevertPost
        });
        bytes memory executionData = abi.encode(f);

        vm.expectRevert(abi.encodeWithSelector(CallForwardingPolicy.PostCallReverted.selector, policyId));
        policyManager.installWithSignature(binding, userSig, executionData);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyInstalled` on first install.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_emitsPolicyInstalled(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory userSig = _signInstall(binding);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyInstalled(policyId, address(account), address(installPolicy));
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Installs a policy instance and writes a lifecycle record.
    ///
    /// @dev Verifies that `policies(policy, policyId)` reflects binding fields.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_installs_andStoresRecord(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        bytes memory userSig = _signInstall(binding);

        bytes32 policyId = policyManager.installWithSignature(binding, userSig, bytes(""));

        (bool installed, bool uninstalled, address recordAccount, uint40 validAfter, uint40 validUntil) =
            policyManager.policies(address(installPolicy), policyId);

        assertTrue(installed);
        assertFalse(uninstalled);
        assertEq(recordAccount, address(account));
        assertEq(validAfter, binding.validAfter);
        assertEq(validUntil, binding.validUntil);
    }

    /// @notice Forwards the manager caller as the effective caller to the policy install hook.
    ///
    /// @dev When installWithSignature is called by a relayer, effectiveCaller = msg.sender (relayer).
    function test_callsOnInstall_forwardsManagerMsgSender_asEffectiveCaller() public {
        address relayer = address(0x123);
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        vm.prank(relayer);
        policyManager.installWithSignature(binding, userSig, bytes(""));

        assertEq(installPolicy.lastEffectiveCaller(), relayer);
        assertEq(installPolicy.lastAccount(), address(account));
    }

    /// @notice Executes immediately when `executionData` is non-empty.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    function test_executes_whenExecutionDataProvided(bytes32 configSeed, uint256 salt, bytes32 tag) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, salt);
        bytes memory userSig = _signInstall(binding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        policyManager.installWithSignature(binding, userSig, executionData);

        assertEq(receiver.calls(), 1);
        assertEq(receiver.lastTag(), tag);
    }

    /// @notice Emits `PolicyExecuted` when `executionData` is non-empty.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    /// @param tag Arbitrary tag forwarded to the receiver call data.
    function test_emitsPolicyExecuted_whenExecutionDataProvided(bytes32 configSeed, uint256 salt, bytes32 tag) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, salt);
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory userSig = _signInstall(binding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyExecuted(policyId, address(account), address(callPolicy), keccak256(executionData));
        policyManager.installWithSignature(binding, userSig, executionData);
    }

    /// @notice Calls the policy execute hook with the immediate manager caller when `executionData` is provided.
    function test_whenExecutionDataProvided_callsPolicyOnExecute_withImmediateCaller() public {
        address relayer = address(0x456);
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        vm.prank(relayer);
        policyManager.installWithSignature(binding, userSig, executionData);

        assertEq(callPolicy.lastManagerCaller(), relayer);
    }

    /// @notice Executes post-call data returned by the policy after calling the account.
    function test_whenExecutionDataProvided_callsPolicyPostCall_afterAccountCall() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory userSig = _signInstall(binding);

        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, bytes32(0)),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.CallPost
        });
        bytes memory executionData = abi.encode(f);

        policyManager.installWithSignature(binding, userSig, executionData);

        assertEq(callPolicy.postCalls(), 1);
        assertEq(callPolicy.lastExecutedPolicyId(), policyId);
    }

    // =============================================================
    // Edge cases
    // =============================================================

    /// @notice Installing an already-installed policyId does not emit `PolicyInstalled` or call install hooks again.
    ///
    /// @dev Second install returns the same policyId; signature is still required.
    ///
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_isIdempotent_noHookNoEventOnSecondInstall(bytes32 configSeed, uint256 salt) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);
        bytes memory userSig = _signInstall(binding);

        bytes32 policyId = policyManager.installWithSignature(binding, userSig, bytes(""));

        vm.recordLogs();
        bytes32 policyId2 = policyManager.installWithSignature(binding, userSig, bytes(""));
        assertEq(policyId2, policyId);
        assertEq(vm.getRecordedLogs().length, 0);
    }

    /// @notice Allows installing multiple otherwise identical bindings via distinct salts.
    ///
    /// @dev Same (account, policy, configHash) but different salts => different policyIds => both installable.
    ///
    /// @param saltA Seed for first salt.
    /// @param saltB Seed for second salt.
    function test_allowsMultipleInstalls_withDifferentSalts(uint256 saltA, uint256 saltB) public {
        vm.assume(saltA != saltB);
        uint256 saltBAdjusted = saltB;

        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory bindingA = _binding(address(installPolicy), policyConfig, saltA);
        PolicyManager.PolicyBinding memory bindingB = _binding(address(installPolicy), policyConfig, saltBAdjusted);

        bytes memory userSigA = _signInstall(bindingA);
        bytes memory userSigB = _signInstall(bindingB);

        bytes32 policyIdA = policyManager.installWithSignature(bindingA, userSigA, bytes(""));
        bytes32 policyIdB = policyManager.installWithSignature(bindingB, userSigB, bytes(""));

        assertTrue(policyIdA != policyIdB);
        (bool installedA,,,,) = policyManager.policies(address(installPolicy), policyIdA);
        (bool installedB,,,,) = policyManager.policies(address(installPolicy), policyIdB);
        assertTrue(installedA);
        assertTrue(installedB);
    }

    /// @notice Stores `validAfter`/`validUntil` from the binding into the policy record.
    ///
    /// @param validAfter Lower-bound timestamp (seconds).
    /// @param validUntil Upper-bound timestamp (seconds).
    /// @param configSeed Seed used to build the committed config bytes.
    /// @param salt Salt used to derive the policyId.
    function test_storesValidityWindow_fieldsInRecord(
        uint40 validAfter,
        uint40 validUntil,
        bytes32 configSeed,
        uint256 salt
    ) public {
        bytes memory policyConfig = abi.encode(_safeConfigSeed(configSeed));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, salt);

        if (validUntil != 0 && validUntil <= validAfter) {
            validUntil = validAfter == type(uint40).max ? 0 : validAfter + 1;
        }
        binding.validAfter = validAfter;
        binding.validUntil = validUntil;

        if (validUntil == 0) {
            uint40 installTs = validAfter;
            if (installTs < WARP_BASE_TIMESTAMP) installTs = WARP_BASE_TIMESTAMP;
            vm.warp(uint256(installTs));
        } else {
            uint40 range = validUntil - validAfter;
            uint40 installTs = validAfter + uint40(uint256(salt) % uint256(range));
            vm.warp(uint256(installTs));
        }

        bytes memory userSig = _signInstall(binding);
        bytes32 policyId = policyManager.installWithSignature(binding, userSig, bytes(""));

        (,,, uint40 recordValidAfter, uint40 recordValidUntil) =
            policyManager.policies(address(installPolicy), policyId);
        assertEq(recordValidAfter, validAfter);
        assertEq(recordValidUntil, validUntil);
    }

    /// @notice Reinstalling a previously uninstalled policyId remains blocked.
    ///
    /// @dev After uninstallation, any future install attempt for that policyId must revert `PolicyIsDisabled`.
    function test_reinstall_afterUninstall_stillBlocked() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        vm.prank(address(account));
        bytes32 policyId = policyManager.install(binding);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), validAfter: 0, validUntil: 0, salt: 0, policyConfig: bytes("")
            }),
            policy: address(installPolicy),
            policyId: policyId,
            policyConfig: policyConfig,
            uninstallData: ""
        });
        vm.prank(address(account));
        policyManager.uninstall(payload);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, policyId));
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Empty `policyConfig` is allowed when the binding commits to its hash.
    function test_allowsEmptyPolicyConfig_whenHashMatches() public {
        bytes memory policyConfig = "";
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice Behavior when `binding.policy` is the zero address.
    ///
    /// @dev Expects revert (policy contract call fails).
    function test_whenPolicyIsZeroAddress_behavior() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(0), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert();
        policyManager.installWithSignature(binding, userSig, bytes(""));
    }

    /// @notice When already-installed, providing `executionData` triggers execution without reinstalling.
    function test_whenAlreadyInstalled_andExecutionDataProvided_executes() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        policyManager.installWithSignature(binding, userSig, bytes(""));
        assertEq(receiver.calls(), 0);

        bytes32 tag = bytes32(uint256(0x123));
        CallForwardingPolicy.ForwardCall memory f = CallForwardingPolicy.ForwardCall({
            target: address(receiver),
            value: 0,
            data: abi.encodeWithSelector(receiver.ping.selector, tag),
            revertOnExecute: false,
            postAction: CallForwardingPolicy.PostAction.None
        });
        bytes memory executionData = abi.encode(f);

        policyManager.installWithSignature(binding, userSig, executionData);

        assertEq(receiver.calls(), 1);
        assertEq(receiver.lastTag(), tag);
    }

    /// @notice Empty `executionData` is allowed and performs install-only.
    function test_allowsEmptyExecutionData() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(installPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        bytes32 policyId = policyManager.installWithSignature(binding, userSig, bytes(""));

        (bool installed,,,,) = policyManager.policies(address(installPolicy), policyId);
        assertTrue(installed);
        assertEq(receiver.calls(), 0);
    }

    /// @notice When `executionData` is empty, installWithSignature does not call execute hooks or emit `PolicyExecuted`.
    function test_whenExecutionDataEmpty_doesNotExecute() public {
        bytes memory policyConfig = abi.encode(bytes32(0));
        PolicyManager.PolicyBinding memory binding = _binding(address(callPolicy), policyConfig, 0);
        bytes memory userSig = _signInstall(binding);

        policyManager.installWithSignature(binding, userSig, bytes(""));

        assertEq(receiver.calls(), 0);
    }
}
