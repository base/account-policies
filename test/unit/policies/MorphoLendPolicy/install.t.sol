// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `MorphoLendPolicy` install-time behavior (`_onAOAInstall`).
contract InstallTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the vault address in the policy config is zero.
    function test_reverts_whenVaultIsZeroAddress() public {
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
