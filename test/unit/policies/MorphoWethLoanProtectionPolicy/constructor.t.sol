// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";
import {MorphoWethLoanProtectionPolicy} from "../../../../src/policies/MorphoWethLoanProtectionPolicy.sol";

import {
    MorphoWethLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoWethLoanProtectionPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `MorphoWethLoanProtectionPolicy` constructor behavior.
contract ConstructorTest is MorphoWethLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoWethLoanProtectionBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the WETH address has no deployed code.
    function test_reverts_whenWethNotContract() public {
        vm.expectRevert(abi.encodeWithSelector(MorphoWethLoanProtectionPolicy.WethNotContract.selector, address(0)));
        new MorphoWethLoanProtectionPolicy(address(policyManager), owner, address(morpho), address(0), 0.05e18);
    }

    /// @notice Reverts when the WETH address is an EOA with no deployed code.
    ///
    /// @param wethAddr Fuzzed address to use as WETH (filtered to have no code).
    function test_reverts_whenWethIsEOA(address wethAddr) public {
        vm.assume(wethAddr.code.length == 0);
        vm.expectRevert(abi.encodeWithSelector(MorphoWethLoanProtectionPolicy.WethNotContract.selector, wethAddr));
        new MorphoWethLoanProtectionPolicy(address(policyManager), owner, address(morpho), wethAddr, 0.05e18);
    }

    /// @notice Reverts when the Morpho Blue address has no deployed code (inherited from parent).
    function test_reverts_whenMorphoNotContract() public {
        vm.expectRevert(abi.encodeWithSelector(MorphoLoanProtectionPolicy.MorphoNotContract.selector, address(0)));
        new MorphoWethLoanProtectionPolicy(address(policyManager), owner, address(0), address(wethToken), 0.05e18);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Stores the WETH address as an immutable.
    ///
    /// @param wethAddr Fuzzed address to use as WETH (given code to pass constructor check).
    function test_storesWethImmutable(address wethAddr) public {
        vm.assume(uint160(wethAddr) > 10);
        vm.etch(wethAddr, hex"00");
        MorphoWethLoanProtectionPolicy p =
            new MorphoWethLoanProtectionPolicy(address(policyManager), owner, address(morpho), wethAddr, 0.05e18);
        assertEq(p.weth(), wethAddr);
        assertEq(p.WETH(), wethAddr);
    }

    /// @notice Stores the Morpho Blue address as an immutable (inherited from parent).
    ///
    /// @param morphoAddr Fuzzed address to use as Morpho (given code to pass constructor check).
    function test_storesMorphoImmutable(address morphoAddr) public {
        vm.assume(uint160(morphoAddr) > 10);
        vm.etch(morphoAddr, hex"00");
        MorphoWethLoanProtectionPolicy p =
            new MorphoWethLoanProtectionPolicy(address(policyManager), owner, morphoAddr, address(wethToken), 0.05e18);
        assertEq(p.morpho(), morphoAddr);
    }
}
