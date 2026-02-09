// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title isPolicyUninstalledTest
///
/// @notice Test contract for `PolicyManager.isPolicyUninstalled`.
contract isPolicyUninstalledTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

