// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title getPolicyIdTest
///
/// @notice Test contract for `PolicyManager.getPolicyId`.
contract getPolicyIdTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Produces the same policyId for the same binding inputs.
    function test_isDeterministic() public {
        vm.skip(true);
    }

    /// @notice Changing `salt` changes the policyId.
    function test_changesWithSalt(uint256 saltA, uint256 saltB) public {
        vm.skip(true);

        saltA;
        saltB;
    }

    /// @notice Changing `policyConfigHash` changes the policyId.
    function test_changesWithPolicyConfigHash(bytes32 policyConfigHashA, bytes32 policyConfigHashB) public {
        vm.skip(true);

        policyConfigHashA;
        policyConfigHashB;
    }

    /// @notice Changing the validity window changes the policyId.
    function test_changesWithValidityWindow(uint40 validAfter, uint40 validUntil) public {
        vm.skip(true);

        validAfter;
        validUntil;
    }

    /// @notice Matches the `POLICY_BINDING_TYPEHASH` field order (regression test against accidental reorder).
    function test_matchesTypehashFieldOrder() public {
        vm.skip(true);
    }
}

