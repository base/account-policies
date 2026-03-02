// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";

import {Policy} from "../../../../src/policies/Policy.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";

import {
    AOAPolicyTestBase,
    AOATestPolicy
} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title SetPolicyManagerTest
///
/// @notice Test contract for `AOAPolicy.setPolicyManager`.
contract SetPolicyManagerTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
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
        policy.setPolicyManager(address(policyManager));
    }

    /// @notice Reverts when the new policy manager address has no deployed code.
    ///
    /// @param newManager Fuzzed non-contract address.
    function test_reverts_whenNewManagerNotContract(address newManager) public {
        vm.assume(newManager.code.length == 0);

        vm.expectRevert(abi.encodeWithSelector(Policy.PolicyManagerNotContract.selector, newManager));
        vm.prank(owner);
        policy.setPolicyManager(newManager);
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Updates the stored policy manager address.
    function test_updatesPolicyManager() public {
        address newManager = address(new AOATestPolicy(address(policyManager), owner));

        vm.prank(owner);
        policy.setPolicyManager(newManager);

        assertEq(address(policy.policyManager()), newManager);
    }

    /// @notice Emits PolicyManagerUpdated with old and new addresses.
    function test_emitsPolicyManagerUpdated() public {
        address newManager = address(new AOATestPolicy(address(policyManager), owner));
        address oldManager = address(policy.policyManager());

        vm.expectEmit(true, true, true, true, address(policy));
        emit AOAPolicy.PolicyManagerUpdated(oldManager, newManager);
        vm.prank(owner);
        policy.setPolicyManager(newManager);
    }
}
