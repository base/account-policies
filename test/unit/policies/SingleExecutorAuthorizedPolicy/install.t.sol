// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";
import {PolicyManager} from "../../../../src/PolicyManager.sol";

import {
    SingleExecutorAuthorizedPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/SingleExecutorAuthorizedPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `SingleExecutorAuthorizedPolicy._onInstall` behavior (config hash storage,
///         SingleExecutorConfig decoding).
contract InstallTest is SingleExecutorAuthorizedPolicyTestBase {
    function setUp() public {
        setUpSingleExecutorBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the SingleExecutorConfig executor is the zero address.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param policySpecificConfig Arbitrary policy-specific config bytes.
    function test_reverts_whenExecutorIsZeroAddress(uint256 salt, bytes calldata policySpecificConfig) public {
        bytes memory badConfig =
            abi.encode(SingleExecutorPolicy.SingleExecutorConfig({executor: address(0)}), policySpecificConfig);
        PolicyManager.PolicyBinding memory b = _binding(badConfig, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(SingleExecutorPolicy.ZeroExecutor.selector);
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
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
            abi.encode(SingleExecutorPolicy.SingleExecutorConfig({executor: executor}), policySpecificConfig);
        PolicyManager.PolicyBinding memory b = _binding(config, salt);
        bytes memory userSig = _signInstall(b);
        policyManager.installWithSignature(b, userSig, 0, bytes(""));

        bytes32 policyId = policyManager.getPolicyId(b);
        assertEq(policy.getConfigHash(policyId), keccak256(config));
    }
}
