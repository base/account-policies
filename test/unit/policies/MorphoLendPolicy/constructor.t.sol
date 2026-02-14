// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `MorphoLendPolicy` constructor behavior.
///
/// @dev AOA-inherited constructor behavior (ZeroAdmin, POLICY_MANAGER, admin role) is covered
///      in `test/unit/policies/AOAPolicy/constructor.t.sol`. This suite covers MorphoLendPolicy-specific
///      constructor logic only.
contract ConstructorTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase();
    }
}
