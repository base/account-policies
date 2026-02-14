// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` install-time behavior (`_onAOAInstall`).
contract InstallTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the Morpho Blue address is zero.
    function test_reverts_whenMorphoIsZeroAddress() public {
        vm.skip(true);
    }

    /// @notice Reverts when the marketId is zero.
    function test_reverts_whenMarketIdIsZero() public {
        vm.skip(true);
    }

    /// @notice Reverts when maxTopUpAssets is zero.
    function test_reverts_whenMaxTopUpIsZero() public {
        vm.skip(true);
    }

    /// @notice Reverts when the Morpho market for the given marketId is not found or not initialized.
    function test_reverts_whenMarketNotFound() public {
        vm.skip(true);
    }

    /// @notice Reverts when a policy is already installed for the same (account, marketId) pair.
    function test_reverts_whenPolicyAlreadyInstalledForMarket() public {
        vm.skip(true);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Stores the config hash on successful install.
    function test_storesConfigHash() public {
        vm.skip(true);
    }
}
