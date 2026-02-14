// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title ExecuteTest
///
/// @notice Test contract for `MorphoLendPolicy` execution behavior (`_onAOAExecute`).
///
/// @dev AOA-inherited execute behavior (pause gate, executor sig, nonce replay, deadline) is covered
///      in `test/unit/policies/AOAPolicy/execute.t.sol`. This suite covers MorphoLendPolicy-specific
///      execution logic only.
contract ExecuteTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the deposit amount is zero.
    function test_reverts_whenDepositAmountIsZero() public {
        vm.skip(true);
    }

    /// @notice Reverts when the deposit exceeds the recurring allowance for the current period.
    function test_reverts_whenExceedsAllowance() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Deposits assets into the Morpho vault on behalf of the account.
    function test_depositsIntoVault() public {
        vm.skip(true);
    }

    /// @notice Approves the vault to spend the deposit token before calling deposit.
    function test_approvesVaultBeforeDeposit() public {
        vm.skip(true);
    }

    /// @notice Updates the recurring allowance usage after a successful deposit.
    function test_updatesAllowanceUsage() public {
        vm.skip(true);
    }

    /// @notice Emits PolicyExecuted on successful execution.
    function test_emitsPolicyExecuted() public {
        vm.skip(true);
    }
}
