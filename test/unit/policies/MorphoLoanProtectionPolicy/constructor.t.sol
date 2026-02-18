// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` constructor behavior.
contract ConstructorTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    /// @notice Reverts when the Morpho Blue address is zero.
    function test_reverts_whenMorphoIsZero() public {
        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroMorpho.selector);
        new MorphoLoanProtectionPolicy(address(policyManager), owner, address(0));
    }

    /// @notice Stores the Morpho Blue address as an immutable.
    ///
    /// @param morphoAddr Non-zero address to pin as Morpho.
    function test_storesMorphoImmutable(address morphoAddr) public {
        vm.assume(morphoAddr != address(0));
        MorphoLoanProtectionPolicy p = new MorphoLoanProtectionPolicy(address(policyManager), owner, morphoAddr);
        assertEq(p.morpho(), morphoAddr);
    }
}
