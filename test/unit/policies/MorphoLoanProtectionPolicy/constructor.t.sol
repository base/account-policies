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

    /// @notice Reverts when the Morpho Blue address has no deployed code.
    function test_reverts_whenMorphoNotContract() public {
        vm.expectRevert(abi.encodeWithSelector(MorphoLoanProtectionPolicy.MorphoNotContract.selector, address(0)));
        new MorphoLoanProtectionPolicy(address(policyManager), owner, address(0));
    }

    /// @notice Stores the Morpho Blue address as an immutable.
    ///
    /// @param morphoAddr Fuzzed address to pin as Morpho (given code to pass constructor check).
    function test_storesMorphoImmutable(address morphoAddr) public {
        vm.assume(uint160(morphoAddr) > 10);
        vm.etch(morphoAddr, hex"00");
        MorphoLoanProtectionPolicy p = new MorphoLoanProtectionPolicy(address(policyManager), owner, morphoAddr);
        assertEq(p.morpho(), morphoAddr);
    }
}
