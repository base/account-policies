// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` execution behavior (`_onAOAExecute`).
///
/// @dev AOA-inherited execute behavior (pause gate, executor sig, nonce replay, deadline) is covered
///      in `test/unit/policies/AOAPolicy/execute.t.sol`. This suite covers
///      MorphoLoanProtectionPolicy-specific execution logic only.
contract ExecuteTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the policy has already been executed (one-shot).
    function test_reverts_whenPolicyAlreadyUsed() public {
        vm.skip(true);
    }

    /// @notice Reverts when the top-up amount is zero.
    function test_reverts_whenTopUpAmountIsZero() public {
        vm.skip(true);
    }

    /// @notice Reverts when the top-up amount exceeds the configured maximum.
    function test_reverts_whenTopUpExceedsMax() public {
        vm.skip(true);
    }

    /// @notice Reverts when the account's position LTV is below the trigger threshold (position is healthy).
    function test_reverts_whenPositionIsHealthy() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Supplies collateral to the Morpho Blue market on behalf of the account.
    function test_suppliesCollateralToMorpho() public {
        vm.skip(true);
    }

    /// @notice Approves the collateral token before calling supplyCollateral.
    function test_approvesCollateralBeforeSupply() public {
        vm.skip(true);
    }

    /// @notice Marks the policy instance as used after execution (one-shot).
    function test_marksPolicyAsUsed() public {
        vm.skip(true);
    }

    /// @notice Emits PolicyExecuted on successful execution.
    function test_emitsPolicyExecuted() public {
        vm.skip(true);
    }
}
