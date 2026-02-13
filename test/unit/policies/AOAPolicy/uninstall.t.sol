// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title uninstallTest
///
/// @notice Test contract for AOA uninstall authorization.
contract UninstallTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }
}

