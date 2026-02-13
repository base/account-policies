// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {AOAPolicyTestBase} from "../../../lib/testBaseContracts/policyTestBaseContracts/AOAPolicyTestBase.sol";

/// @title UnpauseTest
///
/// @notice Test contract for `AOAPolicy.unpause`.
contract UnpauseTest is AOAPolicyTestBase {
    function setUp() public {
        setUpAOABase();
    }
}

