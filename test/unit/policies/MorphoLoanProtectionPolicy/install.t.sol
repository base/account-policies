// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {Id} from "../../../../src/interfaces/morpho/BlueTypes.sol";
import {AOAPolicy} from "../../../../src/policies/AOAPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../../../../src/policies/MorphoLoanProtectionPolicy.sol";

import {
    MorphoLoanProtectionPolicyTestBase
} from "../../../lib/testBaseContracts/policyTestBaseContracts/MorphoLoanProtectionPolicyTestBase.sol";

/// @title InstallTest
///
/// @notice Test contract for `MorphoLoanProtectionPolicy` install-time behavior (`_onAOAInstall`).
contract InstallTest is MorphoLoanProtectionPolicyTestBase {
    function setUp() public {
        setUpMorphoLoanProtectionBase();
    }

    // =============================================================
    // Reverts
    // =============================================================

    /// @notice Reverts when the Morpho Blue address is zero.
    ///
    /// @param salt Salt for deriving a unique policyId.
    function test_reverts_whenMorphoIsZeroAddress(uint256 salt) public {
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                morpho: address(0), marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroMorpho.selector);
        policyManager.installWithSignature(b, config, userSig, bytes(""));
    }

    /// @notice Reverts when the marketId is zero.
    ///
    /// @param salt Salt for deriving a unique policyId.
    function test_reverts_whenMarketIdIsZero(uint256 salt) public {
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                morpho: address(morpho), marketId: Id.wrap(bytes32(0)), triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroMarketId.selector);
        policyManager.installWithSignature(b, config, userSig, bytes(""));
    }

    /// @notice Reverts when maxTopUpAssets is zero.
    ///
    /// @param salt Salt for deriving a unique policyId.
    function test_reverts_whenMaxTopUpIsZero(uint256 salt) public {
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                morpho: address(morpho), marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 0
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroAmount.selector);
        policyManager.installWithSignature(b, config, userSig, bytes(""));
    }

    /// @notice Reverts when the Morpho market for the given marketId is not found or not initialized.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param rawMarketId Fuzzed non-zero market identifier that has not been initialized on the mock.
    function test_reverts_whenMarketNotFound(uint256 salt, uint256 rawMarketId) public {
        rawMarketId = bound(rawMarketId, 1, type(uint256).max);
        vm.assume(rawMarketId != 123); // setUp's market
        Id badMarketId = Id.wrap(bytes32(rawMarketId));

        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                morpho: address(morpho), marketId: badMarketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(abi.encodeWithSelector(MorphoLoanProtectionPolicy.MarketNotFound.selector, badMarketId));
        policyManager.installWithSignature(b, config, userSig, bytes(""));
    }

    /// @notice Reverts when a policy is already installed for the same (account, marketId) pair.
    ///
    /// @param salt Salt for deriving a distinct policyId (must differ from setUp's salt of 0).
    function test_reverts_whenPolicyAlreadyInstalledForMarket(uint256 salt) public {
        salt = bound(salt, 1, type(uint256).max);

        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                morpho: address(morpho), marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({account: address(account), executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(
            abi.encodeWithSelector(
                MorphoLoanProtectionPolicy.PolicyAlreadyInstalledForMarket.selector, address(account), marketId
            )
        );
        policyManager.installWithSignature(b, config, userSig, bytes(""));
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Stores the config hash on successful install.
    ///
    /// @param wrongConfig Arbitrary bytes whose hash differs from the installed config.
    function test_storesConfigHash(bytes calldata wrongConfig) public {
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));

        bytes32 policyId = policyManager.getPolicyId(binding);

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        policyManager.execute(address(policy), policyId, wrongConfig, bytes(""));
    }

    // =============================================================
    // Helpers
    // =============================================================

    function _buildBinding(bytes memory config, uint256 salt)
        internal
        view
        returns (PolicyManager.PolicyBinding memory)
    {
        return PolicyManager.PolicyBinding({
            account: address(account),
            policy: address(policy),
            validAfter: 0,
            validUntil: 0,
            salt: salt,
            policyConfigHash: keccak256(config)
        });
    }
}
