// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {MoiraiDelegate} from "../../../../src/policies/MoiraiDelegate.sol";

import {
    MoiraiDelegateTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MoiraiDelegateTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `MoiraiDelegate._onInstall` behavior.
contract InstallTest is MoiraiDelegateTestBase {
    function setUp() public {
        setUpMoiraiBase();
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Successfully installs with only an unlock timestamp (no executor).
    function test_success_withDelayOnly() public {
        bytes memory config = _buildMoiraiConfig(block.timestamp + 1 days, address(0));
        bytes32 policyId = _buildAndInstall(config, 0);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Successfully installs with only an executor (no time-lock).
    function test_success_withExecutorOnly() public {
        bytes memory config = _buildMoiraiConfig(0, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Successfully installs with both time-lock and executor configured.
    function test_success_withBothConditions() public {
        bytes memory config = _buildMoiraiConfig(block.timestamp + 1 days, executor);
        bytes32 policyId = _buildAndInstall(config, 0);

        assertTrue(policyManager.isPolicyActive(address(policy), policyId));
    }

    /// @notice Successfully installs the same config twice with different salts (different policyIds).
    function test_success_installTwiceWithDifferentSalt() public {
        bytes memory config = _buildMoiraiConfig(0, executor);

        bytes32 policyId1 = _buildAndInstall(config, 0);
        bytes32 policyId2 = _buildAndInstall(config, 1);

        assertTrue(policyId1 != policyId2);
        assertTrue(policyManager.isPolicyActive(address(policy), policyId1));
        assertTrue(policyManager.isPolicyActive(address(policy), policyId2));
    }

    /// @notice Successfully installs a third policy with different config.
    function test_success_installWithDifferentConfig() public {
        bytes memory config1 = _buildMoiraiConfig(0, executor);
        bytes memory config2 = _buildMoiraiConfig(block.timestamp + 7 days, address(0));

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
        bytes memory config = _buildMoiraiConfig(0, address(0));
        PolicyManager.PolicyBinding memory binding = _buildBinding(config, 0);
        bytes memory userSig = _signInstall(binding);

        vm.expectRevert(MoiraiDelegate.NoConditionSpecified.selector);
        policyManager.installWithSignature(binding, userSig, 0, bytes(""));
    }
}

