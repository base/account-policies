// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

import {SingleExecutorAuthorizedPolicyTestBase} from
    "../../../lib/testBaseContracts/policyTestBaseContracts/SingleExecutorAuthorizedPolicyTestBase.sol";

/// @title AccessControlTest
///
/// @notice Tests for SingleExecutorPolicy two-role access control (ADMIN / PAUSER).
contract AccessControlTest is SingleExecutorAuthorizedPolicyTestBase {
    bytes32 internal pauserRole;
    bytes32 internal adminRole;
    address internal pauser;

    function setUp() public {
        setUpSingleExecutorBase();
        pauserRole = policy.PAUSER_ROLE();
        adminRole = policy.DEFAULT_ADMIN_ROLE();
        pauser = makeAddr("pauser");
    }

    // =============================================================
    // Admin grants PAUSER_ROLE
    // =============================================================

    /// @notice Admin can grant PAUSER_ROLE to another address.
    ///
    /// @param newPauser Address to receive PAUSER_ROLE.
    function test_adminCanGrantPauserRole(address newPauser) public {
        vm.assume(newPauser != owner);

        vm.prank(owner);
        policy.grantRole(pauserRole, newPauser);

        assertTrue(policy.hasRole(pauserRole, newPauser));
    }

    /// @notice Emits RoleGranted when admin grants PAUSER_ROLE.
    function test_emitsRoleGranted_whenAdminGrantsPauserRole() public {
        vm.expectEmit(true, true, true, true, address(policy));
        emit IAccessControl.RoleGranted(pauserRole, pauser, owner);
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);
    }

    /// @notice A newly granted pauser can pause the contract.
    function test_grantedPauserCanPause() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.prank(pauser);
        policy.pause();

        assertTrue(policy.paused());
    }

    /// @notice A newly granted pauser can unpause the contract.
    function test_grantedPauserCanUnpause() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.prank(pauser);
        policy.pause();

        vm.prank(pauser);
        policy.unpause();

        assertFalse(policy.paused());
    }

    // =============================================================
    // Admin revokes PAUSER_ROLE
    // =============================================================

    /// @notice Admin can revoke PAUSER_ROLE from an address.
    function test_adminCanRevokePauserRole() public {
        vm.startPrank(owner);
        policy.grantRole(pauserRole, pauser);
        policy.revokeRole(pauserRole, pauser);
        vm.stopPrank();

        assertFalse(policy.hasRole(pauserRole, pauser));
    }

    /// @notice Emits RoleRevoked when admin revokes PAUSER_ROLE.
    function test_emitsRoleRevoked_whenAdminRevokesPauserRole() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.expectEmit(true, true, true, true, address(policy));
        emit IAccessControl.RoleRevoked(pauserRole, pauser, owner);
        vm.prank(owner);
        policy.revokeRole(pauserRole, pauser);
    }

    /// @notice Revoked pauser can no longer pause.
    function test_revokedPauserCannotPause() public {
        vm.startPrank(owner);
        policy.grantRole(pauserRole, pauser);
        policy.revokeRole(pauserRole, pauser);
        vm.stopPrank();

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, pauserRole)
        );
        vm.prank(pauser);
        policy.pause();
    }

    /// @notice Revoked pauser can no longer unpause.
    function test_revokedPauserCannotUnpause() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.prank(pauser);
        policy.pause();

        vm.prank(owner);
        policy.revokeRole(pauserRole, pauser);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, pauserRole)
        );
        vm.prank(pauser);
        policy.unpause();
    }

    // =============================================================
    // Non-admin cannot manage PAUSER_ROLE
    // =============================================================

    /// @notice Non-admin cannot grant PAUSER_ROLE.
    ///
    /// @param nonAdmin Address without DEFAULT_ADMIN_ROLE.
    function test_reverts_whenNonAdminGrantsPauserRole(address nonAdmin) public {
        vm.assume(!policy.hasRole(adminRole, nonAdmin));

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, adminRole)
        );
        vm.prank(nonAdmin);
        policy.grantRole(pauserRole, makeAddr("target"));
    }

    /// @notice Non-admin cannot revoke PAUSER_ROLE.
    ///
    /// @param nonAdmin Address without DEFAULT_ADMIN_ROLE.
    function test_reverts_whenNonAdminRevokesPauserRole(address nonAdmin) public {
        vm.assume(!policy.hasRole(adminRole, nonAdmin));

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAdmin, adminRole)
        );
        vm.prank(nonAdmin);
        policy.revokeRole(pauserRole, owner);
    }

    // =============================================================
    // Pauser cannot perform admin actions
    // =============================================================

    /// @notice Pauser without admin role cannot grant PAUSER_ROLE to others.
    function test_pauserCannotGrantPauserRole() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, adminRole)
        );
        vm.prank(pauser);
        policy.grantRole(pauserRole, makeAddr("other"));
    }

    /// @notice Pauser without admin role cannot call setPolicyManager.
    function test_pauserCannotSetPolicyManager() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, adminRole)
        );
        vm.prank(pauser);
        policy.setPolicyManager(address(policyManager));
    }

    // =============================================================
    // Admin can manage other admins
    // =============================================================

    /// @notice Admin can grant DEFAULT_ADMIN_ROLE to another address.
    ///
    /// @param newAdmin Address to receive DEFAULT_ADMIN_ROLE.
    function test_adminCanGrantAdminRole(address newAdmin) public {
        vm.prank(owner);
        policy.grantRole(adminRole, newAdmin);

        assertTrue(policy.hasRole(adminRole, newAdmin));
    }

    /// @notice A second admin can independently grant PAUSER_ROLE.
    function test_secondAdminCanGrantPauserRole() public {
        address secondAdmin = makeAddr("secondAdmin");

        vm.prank(owner);
        policy.grantRole(adminRole, secondAdmin);

        vm.prank(secondAdmin);
        policy.grantRole(pauserRole, pauser);

        assertTrue(policy.hasRole(pauserRole, pauser));
    }

    /// @notice Pauser can renounce their own PAUSER_ROLE.
    function test_pauserCanRenounceSelf() public {
        vm.prank(owner);
        policy.grantRole(pauserRole, pauser);

        vm.prank(pauser);
        policy.renounceRole(pauserRole, pauser);

        assertFalse(policy.hasRole(pauserRole, pauser));
    }
}
