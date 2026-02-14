// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../src/PolicyManager.sol";

import {PolicyManagerTestBase} from "../../lib/testBaseContracts/PolicyManagerTestBase.sol";

/// @title ConstructorTest
///
/// @notice Test contract for `PolicyManager` constructor behavior.
contract ConstructorTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Stores the validator as an immutable.
    function test_setsPublicERC6492Validator() public {
        assertEq(address(policyManager.PUBLIC_ERC6492_VALIDATOR()), address(validator));
    }
}

