// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title getAccountsForPoliciesTest
///
/// @notice Test contract for `PolicyManager.getAccountsForPolicies`.
contract getAccountsForPoliciesTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns an array of the same length as `policyIds`.
    function test_returnsSameLength(uint256 len) public {
        vm.skip(true);

        len;
    }

    /// @notice Returns zero address for policyIds that have never been installed.
    function test_returnsZeroForUnknownPolicyIds(bytes32 policyId) public {
        vm.skip(true);

        policyId;
    }

    /// @notice Returns the stored account for installed policyIds.
    function test_returnsAccountForInstalledPolicyIds() public {
        vm.skip(true);
    }
}

