// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

import {
    MoiraiDelegateTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegateTestBase.sol";

/// @title UninstallTest
///
/// @notice Test contract for `MoiraiDelegate._onUninstall` behavior.
///
/// @dev Tests call `policy.onUninstall` directly (pranked as the PolicyManager) to isolate
///      authorization from the PolicyManager's try/catch wrapper, enabling specific error assertions.
contract UninstallTest is MoiraiDelegateTestBase {
    bytes internal policyConfig;
    bytes32 internal policyId;

    function setUp() public {
        setUpMoiraiBase();
        policyConfig = _buildMoiraiConfig(0, executor);
        policyId = _buildAndInstall(policyConfig, 0);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Account owner can uninstall successfully.
    function test_success_uninstall() public {
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), validAfter: 0, validUntil: 0, salt: 0, policyConfig: bytes("")
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertFalse(policyManager.isPolicyActive(address(policy), policyId));
        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    /// @notice isExecuted returns false after uninstall, even when the policy was previously executed.
    function test_isExecuted_falseAfterUninstall() public {
        bytes memory executionData = _buildExecutionData(policyId, policyConfig, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
        assertTrue(policy.isExecuted(policyId));

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), validAfter: 0, validUntil: 0, salt: 0, policyConfig: bytes("")
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });
        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertFalse(policy.isExecuted(policyId));
    }

    /// @notice `_onUninstallForReplace` clears state when the policy is replaced by a new binding.
    function test_success_onUninstallForReplace() public {
        bytes memory executionData = _buildExecutionData(policyId, policyConfig, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
        assertTrue(policy.isExecuted(policyId));

        bytes memory newConfig = _buildMoiraiConfig(0, executor);
        PolicyManager.PolicyBinding memory newBinding = _buildBinding(newConfig, 1);
        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        bytes memory userSig = _signReplace(policyId, policyConfig, newPolicyId);

        PolicyManager.ReplacePayload memory payload = PolicyManager.ReplacePayload({
            oldPolicy: address(policy),
            oldPolicyId: policyId,
            oldPolicyConfig: policyConfig,
            oldPolicyReplaceData: "",
            newPolicyReplaceData: "",
            newBinding: newBinding
        });
        policyManager.replaceWithSignature(payload, userSig, 0, bytes(""));

        assertFalse(policyManager.isPolicyActive(address(policy), policyId));
        assertTrue(policyManager.isPolicyActive(address(policy), newPolicyId));
        assertFalse(policy.isExecuted(policyId));
    }

    /// @notice Uninstalling an already-uninstalled policy is idempotent at the PolicyManager level.
    function test_success_uninstall_alreadyUninstalled() public {
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), validAfter: 0, validUntil: 0, salt: 0, policyConfig: bytes("")
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        // Second uninstall is a no-op at the manager level (policyRecordById.uninstalled == true → return early).
        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Non-account caller is rejected by the policy hook and propagated by the manager.
    ///
    /// @param relayer Non-account caller address.
    function test_reverts_whenNonAccountCaller(address relayer) public {
        vm.assume(relayer != address(account));

        vm.expectRevert(abi.encodeWithSelector(SingleExecutorPolicy.Unauthorized.selector, relayer));
        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfig, bytes(""), relayer);
    }
}
