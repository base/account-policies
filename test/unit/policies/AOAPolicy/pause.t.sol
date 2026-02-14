// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title PauseTest
///
/// @notice Test contract for `AOAPolicy.pause`.
contract PauseTest is AOAPolicyTestBase {
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

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, policy.DEFAULT_ADMIN_ROLE()
            )
        );
        vm.prank(caller);
        policy.pause();
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Pauses the policy contract.
    function test_pausesPolicy() public {
        vm.prank(owner);
        policy.pause();

        assertTrue(policy.paused());
    }

    /// @notice Emits the Paused event on successful pause.
    function test_emitsPaused() public {
        vm.expectEmit(true, true, true, true, address(policy));
        emit Pausable.Paused(owner);
        vm.prank(owner);
        policy.pause();
    }
}
