// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title installPolicyWithSignatureTest
///
/// @notice Test contract for `PolicyManager.installPolicyWithSignature`.
contract installPolicyWithSignatureTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

