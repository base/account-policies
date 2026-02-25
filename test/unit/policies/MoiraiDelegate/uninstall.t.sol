// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";

import {
    MoiraiDelegatePolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegatePolicyTestBase.sol";

/// @title UninstallTest
///
/// @notice Tests for `MoiraiDelegate` uninstall behavior.
contract UninstallTest is MoiraiDelegatePolicyTestBase {
    bytes32 internal policyId;
    PolicyManager.PolicyBinding internal binding;
    bytes internal policyConfig;

    function setUp() public {
        setUpInfrastructure();

        bytes memory config = _buildPolicyConfig(_defaultDelegateConfig(block.timestamp + 1, address(0)));
        (policyId, binding) = _install(config, 0);
        policyConfig = config;
    }

    /// @notice Successfully uninstalls an active policy when called by the account.
    function test_uninstalls() public {
        assertTrue(policyManager.isPolicyActive(address(policy), policyId));

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), policyConfig: bytes(""), validAfter: 0, validUntil: 0, salt: 0
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

    /// @notice Uninstalling an already-uninstalled policy is idempotent and does not revert.
    function test_uninstall_isIdempotent() public {
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), policyConfig: bytes(""), validAfter: 0, validUntil: 0, salt: 0
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));

        // Second uninstall: should succeed without reverting.
        vm.prank(address(account));
        policyManager.uninstall(payload);

        assertTrue(policyManager.isPolicyUninstalled(address(policy), policyId));
    }

    /// @notice Emits PolicyUninstalled on successful uninstall.
    function test_emitsPolicyUninstalled() public {
        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: PolicyManager.PolicyBinding({
                account: address(0), policy: address(0), policyConfig: bytes(""), validAfter: 0, validUntil: 0, salt: 0
            }),
            policy: address(policy),
            policyId: policyId,
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.expectEmit(true, true, true, true, address(policyManager));
        emit PolicyManager.PolicyUninstalled(policyId, address(account), address(policy));

        vm.prank(address(account));
        policyManager.uninstall(payload);
    }
}
