// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title IsPolicyUsedTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy.isPolicyUsed`.
contract IsPolicyUsedTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    /// @notice Returns false for a policy that has not been executed.
    function test_returnsFalse_beforeExecution() public view {
        bytes32 policyId = policyManager.getPolicyId(binding);
        assertFalse(policy.isPolicyUsed(policyId));
    }

    /// @notice Returns true for a policy that has been executed.
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_returnsTrue_afterExecution(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, 25 ether);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0, bytes(""));
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        assertTrue(policy.isPolicyUsed(policyId));
    }
}
