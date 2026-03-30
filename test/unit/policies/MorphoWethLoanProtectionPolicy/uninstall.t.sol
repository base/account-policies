// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {SingleExecutorPolicy} from "../../../../src/policies/SingleExecutorPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {
    MorphoWethLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoWethLoanProtectionPolicyTestBase.sol";

/// @title UninstallTest
///
/// @notice Full-flow uninstall tests for `MorphoWethLoanProtectionPolicy` verifying that internal
///         state (`activePolicyByMarket`, `marketKeyByPolicyId`) is properly cleaned up.
contract UninstallTest is MorphoWethLoanProtectionPolicyTestBase {
    bytes32 internal constant SINGLE_EXECUTOR_UNINSTALL_TYPEHASH = keccak256(
        "SingleExecutorUninstall(bytes32 policyId,address account,bytes32 policyConfigHash,uint256 deadline)"
    );

    function setUp() public {
        setUpMorphoWethLoanProtectionBase();
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
        bytes memory newConfig = abi.encode(SingleExecutorPolicy.SingleExecutorConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: newSalt,
            policyConfig: newConfig
        });
        bytes memory userSig = _signInstall(newBinding);
        policyManager.installWithSignature(newBinding, userSig, 0, bytes(""));

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
        bytes memory newConfig = abi.encode(SingleExecutorPolicy.SingleExecutorConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory newBinding = PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: newSalt,
            policyConfig: newConfig
        });
        bytes memory userSig = _signInstall(newBinding);
        policyManager.installWithSignature(newBinding, userSig, 0, bytes(""));
    }

    // =============================================================
    // Helpers
    // =============================================================

    /// @dev Signs an uninstall message using the WETH policy's EIP-712 domain.
    function _signUninstallLocal(bytes32 policyId, bytes32 configHash, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(SINGLE_EXECUTOR_UNINSTALL_TYPEHASH, policyId, address(account), configHash, deadline)
        );
        bytes32 digest = _hashTypedData(address(policy), "Morpho WETH Loan Protection Policy", "1", structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(executorPk, digest);
        return abi.encodePacked(r, s, v);
    }
}
