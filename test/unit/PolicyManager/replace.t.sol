// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";

/// @title replaceTest
///
/// @notice Test contract for `PolicyManager.replace`.
contract ReplaceTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller is not `payload.newBinding.account`.
    ///
    /// @dev Expects `PolicyManager.InvalidSender`.
    function test_reverts_whenCallerNotAccount(address caller) public {
        vm.skip(true);

        caller;
    }

    /// @notice Reverts when `oldPolicy` or `newBinding.policy` is zero.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenOldOrNewPolicyIsZeroAddress() public {
        vm.skip(true);
    }

    /// @notice Reverts when `newPolicyId == oldPolicyId`.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenNewPolicyIdEqualsOldPolicyId() public {
        vm.skip(true);
    }

    /// @notice Reverts when the old policyId is not installed.
    ///
    /// @dev Expects `PolicyManager.PolicyNotInstalled`.
    function test_reverts_whenOldPolicyNotInstalled(bytes32 oldPolicyId) public {
        vm.skip(true);

        oldPolicyId;
    }

    /// @notice Reverts when the old policyId is already uninstalled.
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenOldPolicyIsDisabled() public {
        vm.skip(true);
    }

    /// @notice Reverts when the old policy instance is installed for a different account than `newBinding.account`.
    ///
    /// @dev Expects `PolicyManager.InvalidPayload` (unless end state already reached and returns early).
    function test_reverts_whenOldPolicyAccountMismatch_andOldPolicyStillInstalled() public {
        vm.skip(true);
    }

    /// @notice Reverts when the new policyId is already installed but the old policy is not yet uninstalled.
    ///
    /// @dev Expects `PolicyManager.PolicyAlreadyInstalled` (unless end state already reached and returns early).
    function test_reverts_whenNewPolicyAlreadyInstalled_andOldPolicyNotYetUninstalled() public {
        vm.skip(true);
    }

    /// @notice Reverts when `newPolicyConfig` hash does not match `newBinding.policyConfigHash`.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    function test_reverts_whenNewPolicyConfigHashMismatch(bytes memory newPolicyConfig) public {
        vm.skip(true);

        newPolicyConfig;
    }

    /// @notice Reverts when installing the new policy outside its validity window.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter` / `PolicyManager.AfterValidUntil`.
    function test_reverts_whenNewBindingOutsideValidityWindow(uint40 validAfter, uint40 validUntil) public {
        vm.skip(true);

        validAfter;
        validUntil;
    }

    /// @notice Bubbles a revert when the new policy's replacement install hook reverts.
    function test_reverts_whenNewPolicyOnReplaceReverts() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyUninstalled` for the old policy instance.
    function test_emitsPolicyUninstalled_forOldPolicy() public {
        vm.skip(true);
    }

    /// @notice Emits `PolicyInstalled` for the new policy instance.
    function test_emitsPolicyInstalled_forNewPolicy() public {
        vm.skip(true);
    }

    /// @notice Emits `PolicyReplaced` after uninstalling old and installing new.
    function test_emitsPolicyReplaced() public {
        vm.skip(true);
    }

    /// @notice Calls `onReplace(..., role=OldPolicy)` for the old policy instance.
    function test_callsOnReplace_forOldPolicy() public {
        vm.skip(true);
    }

    /// @notice Calls `onReplace(..., role=NewPolicy)` for the new policy instance.
    function test_callsOnReplace_forNewPolicy() public {
        vm.skip(true);
    }

    /// @notice Old policy uninstall hook revert cannot block replacement when effective caller is the account.
    function test_oldPolicyHookRevert_doesNotBlockReplace() public {
        vm.skip(true);
    }

    // =============================================================
    // Edge cases
    // =============================================================

    /// @notice If the desired end state is already reached, replacement returns early (idempotent).
    function test_isIdempotent_whenEndStateAlreadyReached_returnsEarly() public {
        vm.skip(true);
    }
}

