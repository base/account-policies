// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {TransferSettingsPolicy} from "../../../../src/policies/TransferSettingsPolicy.sol";

import {
    TransferSettingsPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/TransferSettingsPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `TransferSettingsPolicy._onInstall` behavior.
contract InstallTest is TransferSettingsPolicyTestBase {
    function setUp() public {
        setUpTransferSettingsBase();
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Successfully installs with only an unlock timestamp (no executor).
    function test_success_withDelayOnly() public {
        bytes memory config = _buildTransferConfig(block.timestamp + 1 days, address(0));
        bytes32 policyId = _buildAndInstall(config, 0);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Successfully installs with only an executor (no time-lock).
    function test_success_withExecutorOnly() public {
        bytes memory config = _buildTransferConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Successfully installs with both time-lock and executor configured.
    function test_success_withBothConditions() public {
        bytes memory config = _buildTransferConfig(block.timestamp + 1 days, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Successfully installs the same config twice with different salts (different policyIds).
    function test_success_installTwiceWithDifferentSalt() public {
        bytes memory config = _buildTransferConfig(0, executor);

        bytes32 policyId1 = _buildAndInstall(config, 0);
        bytes32 policyId2 = _buildAndInstall(config, 1);

        assertTrue(policyId1 != policyId2);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId1));
        assertTrue(policyManager.isPolicyActive(address(policy), policyId2));
    }

    /// @notice Successfully installs a second policy with different config.
    function test_success_installWithDifferentConfig() public {
        bytes memory config1 = _buildTransferConfig(0, executor);
        bytes memory config2 = _buildTransferConfig(block.timestamp + 7 days, address(0));

        bytes32 policyId1 = _buildAndInstall(config1, 0);
        bytes32 policyId2 = _buildAndInstall(config2, 0);

        assertTrue(policyId1 != policyId2);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId1));
        assertTrue(policyManager.isPolicyActive(address(policy), policyId2));
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when neither executor nor unlock timestamp is configured.
    function test_reverts_withNoCondition() public {
        bytes memory config = _buildTransferConfig(0, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(config, 0);
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(TransferSettingsPolicy.NoConditionSpecified.selector);
        policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the recipient is the zero address.
    function test_reverts_withZeroRecipient() public {
        bytes memory config = _buildTransferConfig(0, executor, address(0), 1, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(config, 0);
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(TransferSettingsPolicy.ZeroRecipient.selector);
        policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the transfer amount is zero.
    function test_reverts_withZeroAmount() public {
        bytes memory config = _buildTransferConfig(0, executor, address(1), 0, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(config, 0);
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(TransferSettingsPolicy.ZeroAmount.selector);
        policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }
}
