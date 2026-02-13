// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title replaceWithSignatureTest
///
/// @notice Test contract for `PolicyManager.replaceWithSignature`.
contract replaceWithSignatureTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the replace payload is invalid (e.g., zero policy addresses, invalid ids).
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenReplacePayloadInvalid() public {
        vm.skip(true);
    }

    /// @notice Reverts when the signature is past its deadline.
    ///
    /// @dev Expects `PolicyManager.DeadlineExpired`.
    function test_reverts_whenDeadlineExpired(uint256 deadline) public {
        vm.skip(true);

        deadline;
    }

    /// @notice Reverts when the account signature is invalid.
    ///
    /// @dev Expects `PolicyManager.InvalidSignature`.
    function test_reverts_whenInvalidSignature(bytes memory userSig) public {
        vm.skip(true);

        userSig;
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

    /// @notice Reverts when `executionData` is provided but the new config does not match the binding.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    function test_reverts_whenExecutionDataProvided_andNewPolicyConfigHashMismatch(bytes memory newPolicyConfig)
        public
    {
        vm.skip(true);

        newPolicyConfig;
    }

    /// @notice Reverts when `newPolicyConfig` hash does not match `newBinding.policyConfigHash` (during replacement).
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

    /// @notice Reverts when executing after replace but the new policyId is disabled.
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenExecutionAfterReplace_andNewPolicyIsDisabled() public {
        vm.skip(true);
    }

    /// @notice Reverts when executing after replace outside the new binding validity window.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter` / `PolicyManager.AfterValidUntil`.
    function test_reverts_whenExecutionAfterReplace_outsideValidityWindow(uint40 validAfter, uint40 validUntil) public {
        vm.skip(true);

        validAfter;
        validUntil;
    }

    /// @notice Bubbles a revert when the policy's `onExecute` hook reverts (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andPolicyOnExecuteReverts() public {
        vm.skip(true);
    }

    /// @notice Bubbles a revert when the account call fails (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andAccountCallReverts() public {
        vm.skip(true);
    }

    /// @notice Bubbles a revert when the post-call fails (when `executionData` is provided).
    function test_reverts_whenExecutionDataProvided_andPostCallReverts() public {
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

    /// @notice Emits `PolicyReplaced` on successful replacement.
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

    /// @notice Returns early without requiring a signature when end state is already reached and no execution is requested.
    function test_isIdempotent_whenEndStateAlreadyReached_andNoExecution_doesNotRequireValidSig() public {
        vm.skip(true);
    }

    /// @notice When `executionData` is empty, replaceWithSignature does not execute or emit `PolicyExecuted`.
    function test_whenExecutionDataEmpty_doesNotExecute() public {
        vm.skip(true);
    }

    /// @notice Performs execution after a successful replacement when `executionData` is provided.
    function test_executesAfterReplace_whenExecutionDataProvided() public {
        vm.skip(true);
    }

    /// @notice Emits `PolicyExecuted` after replacement when `executionData` is provided.
    function test_emitsPolicyExecuted_afterReplace_whenExecutionDataProvided() public {
        vm.skip(true);
    }

    /// @notice When end state is already reached but execution is requested, still requires a valid signature.
    function test_whenEndStateAlreadyReached_andExecutionRequested_requiresValidSig() public {
        vm.skip(true);
    }
}

