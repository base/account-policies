// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {
    SingleExecutorAuthorizedPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/SingleExecutorAuthorizedPolicyTestBase.sol";

/// @title UnpauseTest
///
/// @notice Test contract for `SingleExecutorPolicy.unpause`.
contract UnpauseTest is SingleExecutorAuthorizedPolicyTestBase {
    function setUp() public {
        setUpSingleExecutorBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when caller does not have PAUSER_ROLE.
    ///
    /// @param caller Non-pauser caller.
    function test_reverts_whenCallerLacksPauserRole(address caller) public {
        vm.assume(!policy.hasRole(policy.PAUSER_ROLE(), caller));

        vm.prank(owner);
        policy.pause();

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, policy.PAUSER_ROLE()
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
