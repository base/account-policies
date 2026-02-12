// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManagerTestBase} from "../../lib/PolicyManagerTestBase.sol";

/// @title getPolicyRecordsTest
///
/// @notice Test contract for `PolicyManager.getPolicyRecords`.
contract getPolicyRecordsTest is PolicyManagerTestBase {
    function setUp() public {
        setUpPolicyManagerBase();
    }

    /// @notice Returns arrays with the same length as `policyIds`.
    function test_returnsSameLength(uint256 len) public {
        vm.skip(true);

        len;
    }

    /// @notice Returns default (zero) record fields for unknown policyIds.
    function test_returnsZerosForUnknownPolicyIds(bytes32 policyId) public {
        vm.skip(true);

        policyId;
    }

    /// @notice Returns stored record fields for installed policyIds.
    function test_returnsRecordForInstalledPolicyIds() public {
        vm.skip(true);
    }

    /// @notice Returns `uninstalled = true` for uninstalled policyIds.
    function test_returnsUninstalledForUninstalledPolicyIds() public {
        vm.skip(true);
    }
}

