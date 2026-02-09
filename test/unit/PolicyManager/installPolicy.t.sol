// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title installPolicyTest
///
/// @notice Test contract for `PolicyManager.installPolicy`.
contract installPolicyTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

