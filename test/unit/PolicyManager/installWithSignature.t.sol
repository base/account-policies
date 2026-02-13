// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";

/// @title installWithSignatureTest
///
/// @notice Test contract for `PolicyManager.installWithSignature`.
contract InstallWithSignatureTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the account signature is invalid.
    ///
    /// @dev Expects `PolicyManager.InvalidSignature`.
    function test_reverts_whenInvalidSignature(bytes memory userSig) public {
        vm.skip(true);

        userSig;
    }

    /// @notice Reverts when the policyId has been uninstalled (permanently disabled).
    ///
    /// @dev Expects `PolicyManager.PolicyIsDisabled`.
    function test_reverts_whenPolicyIsDisabled() public {
        vm.skip(true);
    }

    /// @notice Reverts when `policyConfig` hash does not match `binding.policyConfigHash`.
    ///
    /// @dev Expects `PolicyManager.PolicyConfigHashMismatch`.
    function test_reverts_whenPolicyConfigHashMismatch(bytes memory policyConfig) public {
        vm.skip(true);

        policyConfig;
    }

    /// @notice Reverts when current timestamp is before `binding.validAfter`.
    ///
    /// @dev Expects `PolicyManager.BeforeValidAfter`.
    function test_reverts_whenBeforeValidAfter(uint40 validAfter) public {
        vm.skip(true);

        validAfter;
    }

    /// @notice Reverts when current timestamp is at/after `binding.validUntil`.
    ///
    /// @dev Expects `PolicyManager.AfterValidUntil`.
    function test_reverts_whenAfterValidUntil(uint40 validUntil) public {
        vm.skip(true);

        validUntil;
    }

    /// @notice Bubbles a revert when the policy's `onInstall` hook reverts.
    function test_reverts_whenPolicyOnInstallReverts() public {
        vm.skip(true);
    }

    /// @notice Reverts when `executionData` is provided but the supplied config does not match the binding.
    ///
    /// @dev This can occur even when the policyId is already installed, because install is idempotent and skips config
    ///      checks, but execution must still authenticate config.
    function test_reverts_whenExecutionDataProvided_andPolicyConfigHashMismatch() public {
        vm.skip(true);
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

    /// @notice Emits `PolicyInstalled` on first install.
    function test_emitsPolicyInstalled() public {
        vm.skip(true);
    }

    /// @notice Installs a policy instance and writes a lifecycle record.
    ///
    /// @dev Verifies that `policies(policy, policyId)` reflects binding fields.
    function test_installs_andStoresRecord() public {
        vm.skip(true);
    }

    /// @notice Forwards the manager caller as the effective caller to the policy install hook.
    function test_callsOnInstall_forwardsManagerMsgSender_asEffectiveCaller() public {
        vm.skip(true);
    }

    /// @notice Executes immediately when `executionData` is non-empty.
    function test_executes_whenExecutionDataProvided() public {
        vm.skip(true);
    }

    /// @notice Emits `PolicyExecuted` when `executionData` is non-empty.
    function test_emitsPolicyExecuted_whenExecutionDataProvided() public {
        vm.skip(true);
    }

    /// @notice Calls the policy execute hook with the immediate manager caller when `executionData` is provided.
    function test_whenExecutionDataProvided_callsPolicyOnExecute_withImmediateCaller() public {
        vm.skip(true);
    }

    /// @notice Executes post-call data returned by the policy after calling the account.
    function test_whenExecutionDataProvided_callsPolicyPostCall_afterAccountCall() public {
        vm.skip(true);
    }

    // =============================================================
    // Edge cases
    // =============================================================

    /// @notice Installing an already-installed policyId does not emit `PolicyInstalled` or call install hooks again.
    function test_isIdempotent_noHookNoEventOnSecondInstall() public {
        vm.skip(true);
    }

    /// @notice Allows installing multiple otherwise identical bindings via distinct salts.
    ///
    /// @dev Same (account, policy, configHash) but different salts => different policyIds => both installable.
    function test_allowsMultipleInstalls_withDifferentSalts(uint256 saltA, uint256 saltB) public {
        vm.skip(true);

        saltA;
        saltB;
    }

    /// @notice Stores `validAfter`/`validUntil` from the binding into the policy record.
    function test_storesValidityWindow_fieldsInRecord(uint40 validAfter, uint40 validUntil) public {
        vm.skip(true);

        validAfter;
        validUntil;
    }

    /// @notice Reinstalling a previously uninstalled policyId remains blocked.
    ///
    /// @dev After uninstallation, any future install attempt for that policyId must revert `PolicyIsDisabled`.
    function test_reinstall_afterUninstall_stillBlocked() public {
        vm.skip(true);
    }

    /// @notice Empty `policyConfig` is allowed when the binding commits to its hash.
    function test_allowsEmptyPolicyConfig_whenHashMatches() public {
        vm.skip(true);
    }

    /// @notice Behavior when `binding.policy` is the zero address.
    ///
    /// @dev Decide whether this should revert (preferred) or succeed as a no-op policy.
    function test_whenPolicyIsZeroAddress_behavior() public {
        vm.skip(true);
    }

    /// @notice When already-installed, providing `executionData` triggers execution without reinstalling.
    function test_whenAlreadyInstalled_andExecutionDataProvided_executes() public {
        vm.skip(true);
    }

    /// @notice Empty `executionData` is allowed and performs install-only.
    function test_allowsEmptyExecutionData() public {
        vm.skip(true);
    }

    /// @notice When `executionData` is empty, installWithSignature does not call execute hooks or emit `PolicyExecuted`.
    function test_whenExecutionDataEmpty_doesNotExecute() public {
        vm.skip(true);
    }
}

