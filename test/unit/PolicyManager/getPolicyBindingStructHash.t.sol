// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title getPolicyBindingStructHashTest
///
/// @notice Test contract for `PolicyManager.getPolicyId`.
contract getPolicyBindingStructHashTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

