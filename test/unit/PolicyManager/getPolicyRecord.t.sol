// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title getPolicyRecordTest
///
/// @notice Test contract for `PolicyManager.getPolicyRecord`.
contract getPolicyRecordTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

