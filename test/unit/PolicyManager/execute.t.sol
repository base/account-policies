// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title executeTest
///
/// @notice Test contract for `PolicyManager.execute`.
contract executeTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policyId is not installed.
    ///
    /// @dev Expects `PolicyManager.PolicyNotInstalled`.
    function test_reverts_whenPolicyNotInstalled(bytes32 policyId) public {
        vm.skip(true);

        policyId;
    }

    /// @notice Reverts when the policyId is uninstalled (permanently disabled).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenPolicyIsDisabled() public {
        vm.skip(true);
    }

    /// @notice Reverts when current timestamp is before `validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    function test_reverts_whenBeforeValidAfter(uint40 validAfter) public {
        vm.skip(true);

        validAfter;
    }

    /// @notice Reverts when current timestamp is at/after `validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    function test_reverts_whenAfterValidUntil(uint40 validUntil) public {
        vm.skip(true);

        validUntil;
    }

    /// @notice Bubbles a revert when the policy's `onExecute` hook reverts.
    function test_reverts_whenPolicyOnExecuteReverts() public {
        vm.skip(true);
    }

    /// @notice Bubbles a revert when the account call fails.
    function test_reverts_whenAccountCallReverts() public {
        vm.skip(true);
    }

    /// @notice Bubbles a revert when the post-call fails.
    function test_reverts_whenPostCallReverts() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Emits `PolicyExecuted` on successful execution.
    function test_emitsPolicyExecuted() public {
        vm.skip(true);
    }

    /// @notice Calls the policy hook with the immediate manager caller as `caller`.
    function test_callsPolicyOnExecute_withImmediateCaller() public {
        vm.skip(true);
    }

    /// @notice Executes account call data returned by the policy.
    function test_callsAccount_withPolicyPreparedCallData() public {
        vm.skip(true);
    }

    /// @notice Executes post-call data returned by the policy after calling the account.
    function test_callsPolicyPostCall_afterAccountCall() public {
        vm.skip(true);
    }
}

