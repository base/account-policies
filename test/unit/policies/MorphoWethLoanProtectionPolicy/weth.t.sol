// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoWethLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoWethLoanProtectionPolicyTestBase.sol";

/// @title WethTest
///
/// @notice Tests for `MorphoWethLoanProtectionPolicy` view functions and EIP-712 domain.
contract WethTest is MorphoWethLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoWethLoanProtectionBase();
    }

    // =============================================================
    // View functions
    // =============================================================

    /// @notice `weth()` returns the configured WETH address.
    function test_weth_returnsCorrectAddress() public view {
        assertEq(policy.weth(), address(wethToken));
    }

    /// @notice `WETH` immutable matches the configured WETH address.
    function test_WETH_returnsCorrectAddress() public view {
        assertEq(policy.WETH(), address(wethToken));
    }

    /// @notice `morpho()` returns the configured Morpho Blue address (inherited).
    function test_morpho_returnsCorrectAddress() public view {
        assertEq(policy.morpho(), address(morpho));
    }

    /// @notice `isPolicyUsed` returns false before execution.
    function test_isPolicyUsed_returnsFalse_beforeExecution() public view {
        bytes32 policyId = policyManager.getPolicyId(binding);
        assertFalse(policy.isPolicyUsed(policyId));
    }

    /// @notice `isPolicyUsed` returns true after execution.
    ///
    /// @param topUpAssets Amount of collateral to top up.
    /// @param nonce Executor-chosen nonce.
    function test_isPolicyUsed_returnsTrue_afterExecution(uint256 topUpAssets, uint256 nonce) public {
        topUpAssets = bound(topUpAssets, 1, 25 ether);

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory executionData = _encodePolicyData(topUpAssets, nonce, 0);
        policyManager.execute(address(policy), policyId, policyConfig, executionData);

        assertTrue(policy.isPolicyUsed(policyId));
    }

    // =============================================================
    // EIP-712 domain
    // =============================================================

    /// @notice EIP-712 domain name is "Morpho WETH Loan Protection Policy".
    function test_eip712DomainName() public view {
        (, string memory name,,,,,) = policy.eip712Domain();
        assertEq(name, "Morpho WETH Loan Protection Policy");
    }

    /// @notice EIP-712 domain version is "1".
    function test_eip712DomainVersion() public view {
        (,, string memory version,,,,) = policy.eip712Domain();
        assertEq(version, "1");
    }
}
