// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` constructor behavior.
///
/// @dev AOA-inherited constructor behavior (ZeroAdmin, POLICY_MANAGER, admin role) is covered
///      in `test/unit/policies/AOAPolicy/constructor.t.sol`. This suite covers
///      MorphoLoanProtectionPolicy-specific constructor logic only.
contract ConstructorTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }
}
