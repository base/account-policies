// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyInstalledTest
///
/// @notice Test contract for `PolicyManager.isPolicyInstalled`.
contract isPolicyInstalledTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

