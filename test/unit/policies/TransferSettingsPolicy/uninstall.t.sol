// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

import {
    TransferSettingsPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/TransferSettingsPolicyTestBase.sol";

/// @title UninstallTest
///
/// @notice Test contract for `TransferSettingsPolicy._onUninstall` behavior.
///
/// @dev Tests call `policy.onUninstall` directly (pranked as the PolicyManager) to isolate
///      authorization from the PolicyManager's try/catch wrapper, enabling specific error assertions.
contract UninstallTest is TransferSettingsPolicyTestBase {
    bytes internal policyConfig;
    bytes32 internal policyId;

    function setUp() public {
        setUpTransferSettingsBase();
        vm.deal(address(account), 1 ether);
        policyConfig = _buildTransferConfig(0, executor);
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
        assertTrue(policy.executed(policyId));

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

        assertFalse(policy.executed(policyId));
    }

    /// @notice `_onUninstallForReplace` clears state when the policy is replaced by a new binding.
    function test_success_onUninstallForReplace() public {
        bytes memory executionData = _buildExecutionData(policyId, policyConfig, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
        assertTrue(policy.executed(policyId));

        bytes memory newConfig = _buildTransferConfig(0, executor);
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
        assertFalse(policy.executed(policyId));
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

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Non-account, non-executor caller with an invalid signature is rejected.
    ///
    /// @param relayer Non-account, non-executor caller address.
    function test_reverts_whenNonAccountCaller(address relayer) public {
        vm.assume(relayer != address(account) && relayer != executor);

        bytes memory uninstallData = abi.encode(bytes(""), uint256(0));

        vm.expectRevert(abi.encodeWithSelector(SingleExecutorPolicy.Unauthorized.selector, relayer));
        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfig, uninstallData, relayer);
    }

    /// @notice Executor can uninstall via a signed intent, clearing stored state.
    function test_success_executorUninstall() public {
        bytes memory executionData = _buildExecutionData(policyId, policyConfig, bytes(""), 0, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);
        assertTrue(policy.executed(policyId));

        bytes memory uninstallData = _signExecutorUninstall(policyId, keccak256(policyConfig), 0);
        vm.prank(address(policyManager));
        policy.onUninstall(policyId, address(account), policyConfig, uninstallData, executor);

        assertFalse(policy.executed(policyId));
    }

    /// @notice Executor can permanently disable a policyId before the account ever installs it.
    ///
    /// @dev The pre-install path is triggered when `storedConfigHash == 0`. The executor signs over
    ///      `keccak256(policyConfig)` (the config hash, not a stored hash). After the call, any subsequent
    ///      install attempt with the same binding is permanently blocked by the PolicyManager.
    function test_success_preInstallDisable() public {
        // Build a fresh config/policyId that has never been installed.
        bytes memory freshConfig = _buildTransferConfig(0, executor, address(2), 2, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(freshConfig, 99);
        bytes32 freshPolicyId = policyManager.getPolicyId(binding);

        // Confirm it has never been installed.
        assertFalse(policyManager.isPolicyActive(address(policy), freshPolicyId));

        // Executor signs over keccak256(policyConfig) — the pre-install disable path.
        bytes memory uninstallData = _signExecutorUninstall(freshPolicyId, keccak256(freshConfig), 0);

        // Use the PolicyManager's binding-mode uninstall to trigger the pre-install disable path.
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding,
            policy: address(0),
            policyId: bytes32(0),
            policyConfig: bytes(""),
            uninstallData: uninstallData
        });
        vm.prank(executor);
        policyManager.uninstall(payload);

        // After pre-install disable, the PolicyManager permanently marks the policyId as uninstalled.
        assertTrue(policyManager.isPolicyUninstalled(address(policy), freshPolicyId));

        // Attempting to install the same binding now reverts.
        bytes memory userSig = _signInstall(binding);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.PolicyIsDisabled.selector, freshPolicyId));
        policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }

    /// @notice A delay-only config (executor == address(0)) cannot be pre-install disabled.
    ///
    /// @dev There is no executor to authorize the disable, so the pre-install path reverts with Unauthorized.
    function test_reverts_preInstallDisable_whenDelayOnly() public {
        bytes memory delayConfig = _buildTransferConfig(block.timestamp + 1 days, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(delayConfig, 99);
        bytes32 freshPolicyId = policyManager.getPolicyId(binding);

        // No executor — any caller is unauthorized for the pre-install path.
        bytes memory uninstallData = abi.encode(bytes(""), uint256(0));
        vm.expectRevert(abi.encodeWithSelector(SingleExecutorPolicy.Unauthorized.selector, address(this)));
        vm.prank(address(policyManager));
        policy.onUninstall(freshPolicyId, address(account), delayConfig, uninstallData, address(this));
    }

    /// @notice Pre-install disable reverts when the executor signature has an expired deadline.
    function test_reverts_preInstallDisable_whenExpiredDeadline() public {
        bytes memory freshConfig = _buildTransferConfig(0, executor, address(2), 2, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(freshConfig, 99);
        bytes32 freshPolicyId = policyManager.getPolicyId(binding);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory uninstallData = _signExecutorUninstall(freshPolicyId, keccak256(freshConfig), deadline);

        // Advance time past the deadline.
        vm.warp(deadline + 1);

        vm.expectRevert(
            abi.encodeWithSelector(SingleExecutorPolicy.SignatureExpired.selector, block.timestamp, deadline)
        );
        vm.prank(address(policyManager));
        policy.onUninstall(freshPolicyId, address(account), freshConfig, uninstallData, executor);
    }
}
