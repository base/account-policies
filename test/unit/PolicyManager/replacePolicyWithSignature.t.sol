// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title replacePolicyWithSignatureTest
///
/// @notice Test contract for `PolicyManager.replacePolicyWithSignature`.
contract replacePolicyWithSignatureTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }
}

