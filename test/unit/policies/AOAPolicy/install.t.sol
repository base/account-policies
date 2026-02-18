// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `AOAPolicy._onInstall` behavior (config hash storage, AOAConfig decoding).
contract InstallTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the AOAConfig executor is the zero address.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param policySpecificConfig Arbitrary policy-specific config bytes.
    function test_reverts_whenExecutorIsZeroAddress(uint256 salt, bytes calldata policySpecificConfig) public {
        bytes memory badConfig =
            abi.encode(AOAPolicy.AOAConfig({executor: address(0)}), policySpecificConfig);
        PolicyManager.PolicyBinding memory b = _binding(badConfig, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(AOAPolicy.ZeroExecutor.selector);
        policyManager.installWithSignature(b, badConfig, userSig, bytes(""));
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Stores the config hash on successful install.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param policySpecificConfig Arbitrary policy-specific config bytes.
    function test_storesConfigHash(uint256 salt, bytes calldata policySpecificConfig) public {
        bytes memory config =
            abi.encode(AOAPolicy.AOAConfig({executor: executor}), policySpecificConfig);
        PolicyManager.PolicyBinding memory b = _binding(config, salt);
        bytes memory userSig = _signInstall(b);
        policyManager.installWithSignature(b, config, userSig, bytes(""));

        bytes32 policyId = policyManager.getPolicyId(b);
        assertEq(policy.getConfigHash(policyId), keccak256(config));
    }
}
