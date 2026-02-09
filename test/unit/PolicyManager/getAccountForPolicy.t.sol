// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title getAccountForPolicyTest
///
/// @notice Test contract for `PolicyManager.getAccountForPolicy`.
contract getAccountForPolicyTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

