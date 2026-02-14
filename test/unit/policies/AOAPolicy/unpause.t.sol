// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title UnpauseTest
///
/// @notice Test contract for `AOAPolicy.unpause`.
contract UnpauseTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller does not have DEFAULT_ADMIN_ROLE.
    ///
    /// @param caller Non-admin caller.
    function test_reverts_whenCallerLacksAdminRole(address caller) public {
        vm.assume(!policy.hasRole(policy.DEFAULT_ADMIN_ROLE(), caller));

        vm.prank(owner);
        policy.pause();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, policy.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(caller);
        policy.unpause();
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Unpauses the policy contract.
    function test_unpausesPolicy() public {
        vm.prank(owner);
        policy.pause();
        assertTrue(policy.paused());

        vm.prank(owner);
        policy.unpause();
        assertFalse(policy.paused());
    }

    /// @notice Emits the Unpaused event on successful unpause.
    function test_emitsUnpaused() public {
        vm.prank(owner);
        policy.pause();

        vm.expectEmit(true, true, true, true, address(policy));
        emit Pausable.Unpaused(owner);
        vm.prank(owner);
        policy.unpause();
    }
}
