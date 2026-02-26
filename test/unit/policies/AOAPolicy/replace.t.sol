// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {
    AOATestPolicy,
    AOAPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title ReplaceTest
///
/// @notice Tests for replace and replaceWithSignature on AOA policies, verifying that
///         the `_onUninstallForReplace` override skips redundant executor authorization.
contract ReplaceTest is AOAPolicyTestBase {
    uint256 internal constant NEW_SALT = 42;

    bytes internal newPolicyConfig;
    PolicyManager.PolicyBinding internal newBinding;

    function setUp() public {
        setUpAOABase();

        newPolicyConfig = abi.encode(AOAPolicy.AOAConfig({executor: executor}), bytes("new"));
        newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: NEW_SALT,
            policyConfig: newPolicyConfig
        });
    }

    /// @notice Direct `replace` by the account succeeds without any replaceData.
    function test_replace_succeeds_withoutReplaceData() public {
        bytes32 oldPolicyId = policyManager.getPolicyId(binding);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(policy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: policyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.prank(address(account));
        policyManager.replace(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), oldPolicyId));
        assertTrue(policyManager.isPolicyInstalled(address(policy), policyManager.getPolicyId(newBinding)));
    }

    /// @notice `replaceWithSignature` succeeds without executor auth in replaceData.
    ///         The account's EIP-712 replace signature is sufficient authorization.
    function test_replaceWithSignature_succeeds_withoutExecutorAuth() public {
        bytes32 oldPolicyId = policyManager.getPolicyId(binding);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(policy), oldPolicyId, policyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(policy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: policyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        bytes32 ret = policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
        assertEq(ret, newPolicyId);
        assertTrue(policyManager.isPolicyUninstalled(address(policy), oldPolicyId));
        assertTrue(policyManager.isPolicyActive(address(policy), newPolicyId));
    }

    /// @notice `_onAOAUninstall` is called during replacement so subclass cleanup runs.
    function test_replaceWithSignature_callsOnAOAUninstall() public {
        bytes32 oldPolicyId = policyManager.getPolicyId(binding);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(policy), oldPolicyId, policyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(policy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: policyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));

        assertEq(policy.uninstallCalls(), 1);
        assertEq(policy.lastUninstallPolicyId(), oldPolicyId);
        assertEq(policy.lastUninstallAccount(), address(account));
    }

    /// @notice Emits PolicyReplaced with correct old and new policyIds.
    function test_replaceWithSignature_emitsPolicyReplaced() public {
        bytes32 oldPolicyId = policyManager.getPolicyId(binding);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(policy), oldPolicyId, policyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(policy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: policyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyReplaced(oldPolicyId, newPolicyId, address(account), address(policy), address(policy));
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
    }

    /// @notice A third-party relayer can call `replaceWithSignature` (not the account) and
    ///         the replacement succeeds without executor authorization.
    /// @param relayer Fuzzed relayer address (must not be the account).
    function test_replaceWithSignature_succeedsFromRelayer(address relayer) public {
        vm.assume(relayer != address(account) && relayer != address(0));

        bytes32 oldPolicyId = policyManager.getPolicyId(binding);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(address(policy), oldPolicyId, policyConfig, newPolicyId, 0);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(policy),
            oldPolicyId: oldPolicyId,
            oldPolicyConfig: policyConfig,
            replaceData: "",
            newBinding: newBinding
        });

        vm.prank(relayer);
        bytes32 ret = policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));
        assertEq(ret, newPolicyId);
        assertTrue(policyManager.isPolicyUninstalled(address(policy), oldPolicyId));
        assertTrue(policyManager.isPolicyActive(address(policy), newPolicyId));
    }
}
