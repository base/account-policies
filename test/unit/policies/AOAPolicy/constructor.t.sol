// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";

import {
    AOAPolicyTestBase,
    AOATestPolicy
} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `AOAPolicy` constructor behavior.
contract ConstructorTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }

    /// @notice Reverts when admin is the zero address.
    ///
    /// @param policyManagerAddr Fuzzed address for the policy manager (must have code to pass the codesize check).
    function test_reverts_whenAdminIsZeroAddress(address policyManagerAddr) public {
        vm.assume(uint160(policyManagerAddr) > 10);
        vm.etch(policyManagerAddr, hex"00");
        vm.expectRevert(AOAPolicy.ZeroAdmin.selector);
        new AOATestPolicy(policyManagerAddr, address(0));
    }

    /// @notice Stores the PolicyManager address.
    ///
    /// @param policyManagerAddr Fuzzed address to set as PolicyManager (etched with code).
    function test_setsPolicyManager(address policyManagerAddr) public {
        vm.assume(uint160(policyManagerAddr) > 10);
        vm.etch(policyManagerAddr, hex"00");
        AOATestPolicy p = new AOATestPolicy(policyManagerAddr, owner);
        assertEq(address(p.POLICY_MANAGER()), policyManagerAddr);
    }

    /// @notice Grants DEFAULT_ADMIN_ROLE to the admin address.
    ///
    /// @param admin Non-zero admin address.
    function test_grantsAdminRole(address admin) public {
        vm.assume(admin != address(0));
        AOATestPolicy p = new AOATestPolicy(address(policyManager), admin);
        assertTrue(p.hasRole(p.DEFAULT_ADMIN_ROLE(), admin));
    }
}
