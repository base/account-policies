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
