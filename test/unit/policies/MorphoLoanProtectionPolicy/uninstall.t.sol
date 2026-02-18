// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {Id, Market, MarketParams, Position} from "../../../../src/interfaces/morpho/BlueTypes.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {MorphoLoanProtectionHarness} from "../../../lib/MorphoLoanProtectionHarness.sol";
import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title UninstallTest
///
/// @notice Full-flow uninstall tests for `MorphoLoanProtectionPolicy` verifying that internal
///         state (`_activePolicyByMarket`, `_marketKeyByPolicyId`) is properly cleaned up.
contract UninstallTest is MorphoLoanProtectionPolicyTestBase {
    bytes32 internal constant AOA_UNINSTALL_TYPEHASH =
        keccak256("AOAUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)");

    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    // =============================================================
    // Account-initiated uninstall
    // =============================================================

    /// @notice Account-initiated uninstall clears the per-market active policy mapping,
    ///         allowing a new policy for the same market to be installed afterwards.
    function test_clearsMarketState_whenAccountUninstalls() public {
        bytes32 policyId = policyManager.getPolicyId(binding);

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding,
            policy: address(0),
            policyId: bytes32(0),
            policyConfig: bytes(""),
            uninstallData: bytes("")
        });

        vm.prank(address(account));
        policyManager.uninstall(payload);

        // Verify: can reinstall a new policy for the same market (no PolicyAlreadyInstalledForMarket).
        uint256 newSalt = 42;
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory newConfig = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: newSalt,
            policyConfigHash: keccak256(newConfig)
        });
        bytes memory userSig = _signInstall(newBinding);
        policyManager.installWithSignature(newBinding, newConfig, userSig, bytes(""));

        bytes32 newPolicyId = policyManager.getPolicyId(newBinding);
        assertTrue(newPolicyId != policyId);
    }

    // =============================================================
    // Executor-signed uninstall
    // =============================================================

    /// @notice Executor-signed uninstall clears the per-market active policy mapping.
    ///
    /// @param relayer Non-account relayer address.
    function test_clearsMarketState_whenExecutorUninstalls(address relayer) public {
        vm.assume(relayer != address(account));

        bytes32 policyId = policyManager.getPolicyId(binding);
        bytes memory sig = _signUninstallLocal(policyId, keccak256(policyConfig), 0);
        bytes memory uninstallData = abi.encode(sig, uint256(0));

        PolicyManager.UninstallPayload memory payload = PolicyManager.UninstallPayload({
            binding: binding,
            policy: address(0),
            policyId: bytes32(0),
            policyConfig: policyConfig,
            uninstallData: uninstallData
        });

        vm.prank(relayer);
        policyManager.uninstall(payload);

        // Verify: can reinstall a new policy for the same market.
        uint256 newSalt = 42;
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory newConfig = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: newSalt,
            policyConfigHash: keccak256(newConfig)
        });
        bytes memory userSig = _signInstall(newBinding);
        policyManager.installWithSignature(newBinding, newConfig, userSig, bytes(""));
    }

    // =============================================================
    // Helpers
    // =============================================================

    function _signUninstallLocal(bytes32 policyId, bytes32 configHash, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash =
            keccak256(abi.encode(AOA_UNINSTALL_TYPEHASH, policyId, address(account), configHash, deadline));
        bytes32 digest = _hashTypedData(address(policy), "Morpho Loan Protection Policy", "1", structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        return abi.encodePacked(r, s, v);
    }
}

/// @title ClearInstallStateTest
///
/// @notice Harness-based edge case tests for `MorphoLoanProtectionPolicy._clearInstallState`.
///
/// @dev Tests the compound condition `marketKey != bytes32(0) && _activePolicyByMarket[account][marketKey] == policyId`
///      which has three distinct paths: (1) marketKey is zero (skip), (2) active policy doesn't match (skip delete),
///      (3) both conditions true (delete both).
contract ClearInstallStateTest is Test {
    MorphoLoanProtectionHarness internal harness;

    function setUp() public {
        harness = new MorphoLoanProtectionHarness(address(1), address(this), makeAddr("morpho"));
    }

    /// @notice No-op when the market key has already been cleared (or was never set).
    ///
    /// @dev Covers the `marketKey == bytes32(0)` short-circuit in the compound condition.
    ///
    /// @param policyId Fuzzed policy identifier.
    /// @param account Fuzzed account address.
    function test_noOp_whenMarketKeyIsZero(bytes32 policyId, address account) public {
        assertEq(harness.getMarketKeyByPolicyId(policyId), bytes32(0));

        harness.exposed_clearInstallState(policyId, account);

        assertEq(harness.getMarketKeyByPolicyId(policyId), bytes32(0));
    }

    /// @notice Deletes the market key mapping but leaves the active policy mapping intact
    ///         when a different policyId owns the market slot.
    ///
    /// @dev Covers the `_activePolicyByMarket[account][marketKey] != policyId` path where
    ///      the first condition is true but the second is false.
    ///
    /// @param policyId Policy being cleared.
    /// @param otherPolicyId Different policy that currently owns the market slot.
    /// @param marketKey Market key linking the two mappings.
    /// @param account Account address.
    function test_deletesMarketKey_butNotActivePolicy_whenMismatch(
        bytes32 policyId,
        bytes32 otherPolicyId,
        bytes32 marketKey,
        address account
    ) public {
        vm.assume(marketKey != bytes32(0));
        vm.assume(policyId != otherPolicyId);

        harness.setMarketKeyByPolicyId(policyId, marketKey);
        harness.setActivePolicyByMarket(account, marketKey, otherPolicyId);

        harness.exposed_clearInstallState(policyId, account);

        assertEq(harness.getMarketKeyByPolicyId(policyId), bytes32(0));
        assertEq(harness.getActivePolicyByMarket(account, marketKey), otherPolicyId);
    }

    /// @notice Clears both mappings when the policy owns the market slot (normal uninstall path).
    ///
    /// @param policyId Policy being cleared.
    /// @param marketKey Market key linking the two mappings.
    /// @param account Account address.
    function test_clearsBoth_whenNormalState(bytes32 policyId, bytes32 marketKey, address account) public {
        vm.assume(marketKey != bytes32(0));

        harness.setMarketKeyByPolicyId(policyId, marketKey);
        harness.setActivePolicyByMarket(account, marketKey, policyId);

        harness.exposed_clearInstallState(policyId, account);

        assertEq(harness.getMarketKeyByPolicyId(policyId), bytes32(0));
        assertEq(harness.getActivePolicyByMarket(account, marketKey), bytes32(0));
    }
}
