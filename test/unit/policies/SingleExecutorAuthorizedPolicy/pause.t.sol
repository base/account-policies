// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccessControl} from "openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {Pausable} from "openzeppelin-contracts/contracts/utils/Pausable.sol";

import {
    SingleExecutorAuthorizedPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/SingleExecutorAuthorizedPolicyTestBase.sol";

/// @title PauseTest
///
/// @notice Test contract for `SingleExecutorPolicy.pause`.
contract PauseTest is SingleExecutorAuthorizedPolicyTestBase {
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

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, caller, policy.PAUSER_ROLE()
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
