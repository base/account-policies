// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PublicERC6492Validator} from "../../../src/PublicERC6492Validator.sol";
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

    /// @notice Reverts when the validator address has no deployed code.
    ///
    /// @param validatorAddr Fuzzed non-contract address.
    function test_reverts_whenValidatorNotContract(address validatorAddr) public {
        vm.assume(validatorAddr.code.length == 0);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.ValidatorNotContract.selector, validatorAddr));
        new PolicyManager(PublicERC6492Validator(validatorAddr));
    }
}

