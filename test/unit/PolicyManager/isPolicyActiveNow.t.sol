// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyActiveNowTest
///
/// @notice Test contract for `PolicyManager.isPolicyActiveNow`.
contract isPolicyActiveNowTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

