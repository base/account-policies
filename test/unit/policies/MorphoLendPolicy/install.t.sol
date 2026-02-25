// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MorphoLendPolicy} from "../../../../src/policies/MorphoLendPolicy.sol";

import {
    MorphoLendPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLendPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `MorphoLendPolicy` install-time behavior (`_onAOAInstall`).
contract InstallTest is MorphoLendPolicyTestBase {
    function setUp() public {
        setUpMorphoLendBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the vault address in the policy config is zero.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param allowance Fuzzed allowance (irrelevant — revert fires before use).
    /// @param period Fuzzed period (irrelevant — revert fires before use).
    function test_reverts_whenVaultIsZeroAddress(uint256 salt, uint160 allowance, uint40 period) public {
        bytes memory policySpecificConfig = abi.encode(
            MorphoLendPolicy.LendPolicyConfig({
                vault: address(0),
                depositLimit: MorphoLendPolicy.DepositLimitConfig({allowance: allowance, period: period})
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), policySpecificConfig);

        PolicyManager.PolicyBinding memory b = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfig: config
        });
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MorphoLendPolicy.ZeroVault.selector);
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Stores the config hash on successful install.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param allowance Fuzzed deposit allowance.
    /// @param period Fuzzed period length (bounded >= 1 to avoid division by zero in view helpers).
    function test_storesConfigHash(uint256 salt, uint160 allowance, uint40 period) public {
        allowance = uint160(bound(allowance, 1, type(uint160).max));
        period = uint40(bound(period, 1, type(uint40).max));

        bytes memory policySpecificConfig = abi.encode(
            MorphoLendPolicy.LendPolicyConfig({
                vault: address(vault),
                depositLimit: MorphoLendPolicy.DepositLimitConfig({allowance: allowance, period: period})
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), policySpecificConfig);

        PolicyManager.PolicyBinding memory b = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfig: config
        });
        bytes memory userSig = _signInstall(b);
        policyManager.installWithSignature(b, userSig, 0, bytes(""));

        bytes32 policyId = policyManager.getPolicyId(b);
        // getDepositLimitPeriodUsage calls _requireConfigHash internally — success proves the hash was stored
        policy.getDepositLimitPeriodUsage(policyId, address(account), config);
    }
}
