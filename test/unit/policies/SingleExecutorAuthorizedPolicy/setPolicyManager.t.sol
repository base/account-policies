// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

import {Policy} from "../../../../src/policies/Policy.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";

import {
    SingleExecutorAuthorizedPolicyTestBase,
    SingleExecutorAuthorizedTestPolicy
} from "../../../lib/testBaseContracts/policyTestBaseContracts/SingleExecutorAuthorizedPolicyTestBase.sol";

/// @title AddPolicyManagerTest
///
/// @notice Test contract for `SingleExecutorPolicy.addPolicyManager`.
contract AddPolicyManagerTest is SingleExecutorAuthorizedPolicyTestBase {
    function setUp() public {
        setUpSingleExecutorBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller lacks DEFAULT_ADMIN_ROLE.
    ///
    /// @param caller Non-admin caller.
    function test_reverts_whenCallerLacksAdminRole(address caller) public {
        vm.assume(!policy.hasRole(policy.DEFAULT_ADMIN_ROLE(), caller));
        address newManager = address(new SingleExecutorAuthorizedTestPolicy(address(policyManager), owner));

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, policy.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(caller);
        policy.addPolicyManager(newManager);
    }

    /// @notice Reverts when the new policy manager address has no deployed code.
    ///
    /// @param newManager Fuzzed non-contract address.
    function test_reverts_whenNewManagerNotContract(address newManager) public {
        vm.assume(newManager.code.length == 0);

        vm.expectRevert(abi.encodeWithSelector(Policy.PolicyManagerNotContract.selector, newManager));
        vm.prank(owner);
        policy.addPolicyManager(newManager);
    }

    /// @notice Reverts when the manager is already authorized.
    function test_reverts_whenManagerAlreadyAuthorized() public {
        vm.expectRevert(
            abi.encodeWithSelector(SingleExecutorPolicy.ManagerAlreadyAuthorized.selector, address(policyManager))
        );
        vm.prank(owner);
        policy.addPolicyManager(address(policyManager));
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Adds a new authorized manager.
    function test_addsNewManager() public {
        address newManager = address(new SingleExecutorAuthorizedTestPolicy(address(policyManager), owner));

        vm.prank(owner);
        policy.addPolicyManager(newManager);

        assertTrue(policy.isAuthorizedManager(newManager));
        assertEq(policy.managerCount(), 2);
    }

    /// @notice Emits PolicyManagerAdded when a new manager is authorized.
    function test_emitsPolicyManagerAdded() public {
        address newManager = address(new SingleExecutorAuthorizedTestPolicy(address(policyManager), owner));

        vm.expectEmit(true, true, true, true, address(policy));
        emit SingleExecutorPolicy.PolicyManagerAdded(newManager);
        vm.prank(owner);
        policy.addPolicyManager(newManager);
    }
}

/// @title RemovePolicyManagerTest
///
/// @notice Test contract for `SingleExecutorPolicy.removePolicyManager`.
contract RemovePolicyManagerTest is SingleExecutorAuthorizedPolicyTestBase {
    address internal secondManager;

    function setUp() public {
        setUpSingleExecutorBase();

        // Add a second manager so we can test removal without hitting the "last manager" guard.
        secondManager = address(new SingleExecutorAuthorizedTestPolicy(address(policyManager), owner));
        vm.prank(owner);
        policy.addPolicyManager(secondManager);
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller lacks DEFAULT_ADMIN_ROLE.
    ///
    /// @param caller Non-admin caller.
    function test_reverts_whenCallerLacksAdminRole(address caller) public {
        vm.assume(!policy.hasRole(policy.DEFAULT_ADMIN_ROLE(), caller));

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, policy.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(caller);
        policy.removePolicyManager(secondManager);
    }

    /// @notice Reverts when the manager is not currently authorized.
    ///
    /// @param unknownManager Fuzzed address that is not an authorized manager.
    function test_reverts_whenManagerNotAuthorized(address unknownManager) public {
        vm.assume(!policy.isAuthorizedManager(unknownManager));

        vm.expectRevert(abi.encodeWithSelector(SingleExecutorPolicy.ManagerNotAuthorized.selector, unknownManager));
        vm.prank(owner);
        policy.removePolicyManager(unknownManager);
    }

    /// @notice Reverts when attempting to remove the last remaining manager.
    function test_reverts_whenRemovingLastManager() public {
        // Remove secondManager first, leaving only the original.
        vm.prank(owner);
        policy.removePolicyManager(secondManager);

        vm.expectRevert(SingleExecutorPolicy.CannotRemoveLastManager.selector);
        vm.prank(owner);
        policy.removePolicyManager(address(policyManager));
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Removes an authorized manager.
    function test_removesManager() public {
        vm.prank(owner);
        policy.removePolicyManager(secondManager);

        assertFalse(policy.isAuthorizedManager(secondManager));
        assertEq(policy.managerCount(), 1);
    }

    /// @notice Emits PolicyManagerRemoved when a manager is deauthorized.
    function test_emitsPolicyManagerRemoved() public {
        vm.expectEmit(true, true, true, true, address(policy));
        emit SingleExecutorPolicy.PolicyManagerRemoved(secondManager);
        vm.prank(owner);
        policy.removePolicyManager(secondManager);
    }
}
