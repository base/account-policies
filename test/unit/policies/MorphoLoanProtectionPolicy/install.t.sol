// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PolicyManager} from "../../../../src/PolicyManager.sol";
import {Id, Market, MarketParams} from "../../../../src/interfaces/morpho/BlueTypes.sol";
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

    /// @notice Reverts when the marketId is zero.
    ///
    /// @param salt Salt for deriving a unique policyId.
    function test_reverts_whenMarketIdIsZero(uint256 salt) public {
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: Id.wrap(bytes32(0)), triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroMarketId.selector);
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
    }

    /// @notice Reverts when maxTopUpAssets is zero.
    ///
    /// @param salt Salt for deriving a unique policyId.
    function test_reverts_whenMaxTopUpIsZero(uint256 salt) public {
        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 0
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(MorphoLoanProtectionPolicy.ZeroAmount.selector);
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
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
                marketId: badMarketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(abi.encodeWithSelector(MorphoLoanProtectionPolicy.MarketNotFound.selector, badMarketId));
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
    }

    /// @notice Reverts when triggerLtv is greater than or equal to the market's LLTV.
    ///
    /// @param salt Salt for deriving a unique policyId.
    /// @param triggerLtv Fuzzed trigger LTV at or above the market's LLTV (0.8e18).
    function test_reverts_whenTriggerLtvAboveLltv(uint256 salt, uint256 triggerLtv) public {
        triggerLtv = bound(triggerLtv, marketParams.lltv, type(uint256).max);

        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: marketId, triggerLtv: triggerLtv, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(
            abi.encodeWithSelector(
                MorphoLoanProtectionPolicy.TriggerLtvAboveLltv.selector, triggerLtv, marketParams.lltv
            )
        );
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
    }

    /// @notice Reverts when the Morpho market has lastUpdate == 0 (not created via createMarket).
    ///
    /// @param salt Salt for deriving a unique policyId.
    function test_reverts_whenMarketLastUpdateIsZero(uint256 salt) public {
        Id staleMarketId = Id.wrap(bytes32(uint256(999)));
        MarketParams memory staleParams = MarketParams({
            loanToken: address(loanToken),
            collateralToken: address(collateralToken),
            oracle: address(oracle),
            irm: address(0xBEEF),
            lltv: 0.8e18
        });
        morpho.setMarket(
            staleMarketId,
            staleParams,
            Market({
                totalSupplyAssets: 0,
                totalSupplyShares: 0,
                totalBorrowAssets: 0,
                totalBorrowShares: 0,
                lastUpdate: 0,
                fee: 0
            })
        );

        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: staleMarketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(abi.encodeWithSelector(MorphoLoanProtectionPolicy.MarketNotFound.selector, staleMarketId));
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
    }

    /// @notice Reverts when a policy is already installed for the same (account, marketId) pair.
    ///
    /// @param salt Salt for deriving a distinct policyId (must differ from setUp's salt of 0).
    function test_reverts_whenPolicyAlreadyInstalledForMarket(uint256 salt) public {
        salt = bound(salt, 1, type(uint256).max);

        bytes memory psc = abi.encode(
            MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                marketId: marketId, triggerLtv: 0.7e18, maxTopUpAssets: 25 ether
            })
        );
        bytes memory config = abi.encode(AOAPolicy.AOAConfig({executor: executor}), psc);
        PolicyManager.PolicyBinding memory b = _buildBinding(config, salt);
        bytes memory userSig = _signInstall(b);

        vm.expectRevert(
            abi.encodeWithSelector(
                MorphoLoanProtectionPolicy.PolicyAlreadyInstalledForMarket.selector, address(account), marketId
            )
        );
        policyManager.installWithSignature(b, userSig, 0, bytes(""));
    }

    // =============================================================
    // Success
    // =============================================================

    /// @notice Stores the config hash on successful install.
    ///
    /// @param wrongConfig Arbitrary bytes whose hash differs from the installed config.
    /// @param executionData Arbitrary non-empty execution data (empty executionData causes the policy
    ///        to return early before the config hash check).
    function test_storesConfigHash(bytes calldata wrongConfig, bytes calldata executionData) public {
        vm.assume(keccak256(wrongConfig) != keccak256(policyConfig));
        vm.assume(executionData.length > 0);

        bytes32 policyId = policyManager.getPolicyId(binding);

        vm.expectRevert(
            abi.encodeWithSelector(
                AOAPolicy.PolicyConfigHashMismatch.selector, keccak256(wrongConfig), keccak256(policyConfig)
            )
        );
        policyManager.execute(address(policy), policyId, wrongConfig, executionData);
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
            policyConfig: config
        });
    }
}
