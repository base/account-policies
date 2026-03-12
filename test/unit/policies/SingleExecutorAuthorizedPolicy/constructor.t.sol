// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

import {
    SingleExecutorAuthorizedPolicyTestBase,
    SingleExecutorAuthorizedTestPolicy
} from "../../../lib/testBaseContracts/policyTestBaseContracts/SingleExecutorAuthorizedPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `SingleExecutorPolicy` constructor behavior.
contract ConstructorTest is SingleExecutorAuthorizedPolicyTestBase {
    function setUp() public {
        setUpSingleExecutorBase();
    }

    /// @notice Reverts when admin is the zero address.
    ///
    /// @param policyManagerAddr Fuzzed address for the policy manager (must have code to pass the codesize check).
    function test_reverts_whenAdminIsZeroAddress(address policyManagerAddr) public {
        vm.assume(uint160(policyManagerAddr) > 10);
        vm.etch(policyManagerAddr, hex"00");
        vm.expectRevert(SingleExecutorPolicy.ZeroAdmin.selector);
        new SingleExecutorAuthorizedTestPolicy(policyManagerAddr, address(0));
    }

    /// @notice Stores the PolicyManager address.
    ///
    /// @param policyManagerAddr Fuzzed address to set as PolicyManager (etched with code).
    function test_setsPolicyManager(address policyManagerAddr) public {
        vm.assume(uint160(policyManagerAddr) > 10);
        vm.etch(policyManagerAddr, hex"00");
        SingleExecutorAuthorizedTestPolicy p = new SingleExecutorAuthorizedTestPolicy(policyManagerAddr, owner);
        assertEq(address(p.policyManager()), policyManagerAddr);
    }

    /// @notice Grants DEFAULT_ADMIN_ROLE to the admin address.
    ///
    /// @param admin Non-zero admin address.
    function test_grantsAdminRole(address admin) public {
        vm.assume(admin != address(0));
        SingleExecutorAuthorizedTestPolicy p = new SingleExecutorAuthorizedTestPolicy(address(policyManager), admin);
        assertTrue(p.hasRole(p.DEFAULT_ADMIN_ROLE(), admin));
    }

    /// @notice Grants PAUSER_ROLE to the admin address.
    ///
    /// @param admin Non-zero admin address.
    function test_grantsPauserRole(address admin) public {
        vm.assume(admin != address(0));
        SingleExecutorAuthorizedTestPolicy p =
            new SingleExecutorAuthorizedTestPolicy(address(policyManager), admin);
        assertTrue(p.hasRole(p.PAUSER_ROLE(), admin));
    }
}
