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

    /// @notice Reverts when the replace payload is invalid (e.g., zero policy addresses).
    ///
    /// @dev Expects `PolicyManager.InvalidPayload`.
    function test_reverts_whenInvalidPayload() public {
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

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyReplaced` on successful replacement.
    function test_emitsPolicyReplaced() public {
        vm.skip(true);
    }

    /// @notice Returns early without requiring a signature when end state is already reached and no execution is requested.
    function test_isIdempotent_whenEndStateAlreadyReached_andNoExecution_doesNotRequireValidSig() public {
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

