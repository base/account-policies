// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test, console2} from "forge-std/Test.sol";

import {PolicyManager} from "../../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../../src/policies/MorphoLendPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../../src/policies/MorphoLoanProtectionPolicy.sol";
import {MorphoWethLoanProtectionPolicy} from "../../src/policies/MorphoWethLoanProtectionPolicy.sol";
import {SingleExecutorPolicy} from "../../src/policies/SingleExecutorPolicy.sol";

import {Id, MarketParams} from "../../src/interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../../src/interfaces/morpho/IMorphoBlue.sol";

/// @title BaseForkInstallTest
///
/// @notice Fork test that triggers PolicyInstalled events for each of the 3 active policies deployed on Base mainnet.
///
/// @dev Run with: forge test --match-contract BaseForkInstallTest -vvvv
///
///      Deployed addresses (Base mainnet):
///        PolicyManager:                  0x75b3015780776952102a8bFA6202d2e3c1F4EFc5
///        MorphoLendPolicy:               0x015Cf8dbB7F1045280B96d0afd308dFa7AcB84F0
///        MorphoLoanProtectionPolicy:     0x001B6f938eA6D0A57D02B3e9503b958149A2a7e3
///        MorphoWethLoanProtectionPolicy: 0xe14A101ADF9AE492Dd8e9D2ED7763460A6AE8Cd7
contract BaseForkInstallTest is Test {
    ////////////////////////////////////////////////////////////////
    ///               Deployed Contracts (Base)                  ///
    ////////////////////////////////////////////////////////////////

    PolicyManager constant POLICY_MANAGER = PolicyManager(0x75b3015780776952102a8bFA6202d2e3c1F4EFc5);
    address constant MORPHO_LEND_POLICY = 0x015Cf8dbB7F1045280B96d0afd308dFa7AcB84F0;
    address constant MORPHO_LOAN_PROTECTION_POLICY = 0x001B6f938eA6D0A57D02B3e9503b958149A2a7e3;
    address constant MORPHO_WETH_LOAN_PROTECTION_POLICY = 0xe14A101ADF9AE492Dd8e9D2ED7763460A6AE8Cd7;

    IMorphoBlue constant MORPHO_BLUE = IMorphoBlue(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb);

    ////////////////////////////////////////////////////////////////
    ///               Well-known Base Addresses                  ///
    ////////////////////////////////////////////////////////////////

    /// @dev Moonwell mwUSDC MetaMorpho vault on Base.
    address constant MOONWELL_USDC_VAULT = 0xc1256Ae5FF1cf2719D4937adb3bbCCab2E00A2Ca;

    /// @dev cbBTC/USDC market on Morpho Blue (cbBTC collateral, USDC loan token).
    ///      lltv = 86%.
    Id constant CBBTC_USDC_MARKET_ID = Id.wrap(0x9103c3b4e834476c9a62ea009ba2c884ee42e94e6e314a26f04d312434191836);

    /// @dev WETH/USDC market on Morpho Blue (WETH collateral, USDC loan token).
    ///      lltv = 86%.
    Id constant WETH_USDC_MARKET_ID = Id.wrap(0x8793cf302b8ffd655ab97bd1c695dbd967807e8367a65cb2f4edaf1380ba1bda);

    ////////////////////////////////////////////////////////////////
    ///                     Test State                           ///
    ////////////////////////////////////////////////////////////////

    address account;
    address executor;

    function setUp() public {
        vm.createSelectFork("base");

        account = makeAddr("account");
        executor = makeAddr("executor");

        vm.label(address(POLICY_MANAGER), "PolicyManager");
        vm.label(MORPHO_LEND_POLICY, "MorphoLendPolicy");
        vm.label(MORPHO_LOAN_PROTECTION_POLICY, "MorphoLoanProtectionPolicy");
        vm.label(MORPHO_WETH_LOAN_PROTECTION_POLICY, "MorphoWethLoanProtectionPolicy");
        vm.label(address(MORPHO_BLUE), "MorphoBlue");
    }

    ////////////////////////////////////////////////////////////////
    ///                       Tests                              ///
    ////////////////////////////////////////////////////////////////

    /// @notice Installs MorphoLendPolicy and emits PolicyInstalled.
    function test_installMorphoLendPolicy() public {
        bytes memory policyConfig = abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor}),
            abi.encode(
                MorphoLendPolicy.LendPolicyConfig({
                    vault: MOONWELL_USDC_VAULT,
                    depositLimit: MorphoLendPolicy.DepositLimitConfig({
                        allowance: 1_000_000e6, // 1M USDC per period
                        period: 1 days
                    })
                })
            )
        );

        PolicyManager.PolicyBinding memory binding = _buildBinding(MORPHO_LEND_POLICY, policyConfig, 0);
        bytes32 policyId = POLICY_MANAGER.getPolicyId(binding);

        vm.expectEmit(true, true, true, false);
        emit PolicyManager.PolicyInstalled(policyId, account, MORPHO_LEND_POLICY);

        vm.prank(account);
        POLICY_MANAGER.install(binding);

        assertTrue(POLICY_MANAGER.isPolicyInstalled(MORPHO_LEND_POLICY, policyId));
        console2.log("MorphoLendPolicy installed, policyId:", vm.toString(policyId));
    }

    /// @notice Installs MorphoLoanProtectionPolicy (cbBTC collateral market) and emits PolicyInstalled.
    function test_installMorphoLoanProtectionPolicy() public {
        // Read the market's lltv to compute a safe triggerLtv (50% of lltv is safely within range).
        MarketParams memory marketParams = MORPHO_BLUE.idToMarketParams(CBBTC_USDC_MARKET_ID);
        uint256 triggerLtv = marketParams.lltv / 2;

        console2.log("cbBTC/USDC market lltv:", marketParams.lltv);
        console2.log("triggerLtv:", triggerLtv);

        bytes memory policyConfig = abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor}),
            abi.encode(
                MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                    marketId: CBBTC_USDC_MARKET_ID,
                    triggerLtv: triggerLtv,
                    maxTopUpAssets: 1e8 // 1 cbBTC (8 decimals)
                })
            )
        );

        PolicyManager.PolicyBinding memory binding = _buildBinding(MORPHO_LOAN_PROTECTION_POLICY, policyConfig, 0);
        bytes32 policyId = POLICY_MANAGER.getPolicyId(binding);

        vm.expectEmit(true, true, true, false);
        emit PolicyManager.PolicyInstalled(policyId, account, MORPHO_LOAN_PROTECTION_POLICY);

        vm.prank(account);
        POLICY_MANAGER.install(binding);

        assertTrue(POLICY_MANAGER.isPolicyInstalled(MORPHO_LOAN_PROTECTION_POLICY, policyId));
        console2.log("MorphoLoanProtectionPolicy installed, policyId:", vm.toString(policyId));
    }

    /// @notice Installs MorphoWethLoanProtectionPolicy (WETH collateral market) and emits PolicyInstalled.
    function test_installMorphoWethLoanProtectionPolicy() public {
        // Read the market's lltv to compute a safe triggerLtv (50% of lltv is safely within range).
        MarketParams memory marketParams = MORPHO_BLUE.idToMarketParams(WETH_USDC_MARKET_ID);
        uint256 triggerLtv = marketParams.lltv / 2;

        console2.log("WETH/USDC market lltv:", marketParams.lltv);
        console2.log("WETH collateral token:", marketParams.collateralToken);
        console2.log("triggerLtv:", triggerLtv);

        bytes memory policyConfig = abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor}),
            abi.encode(
                MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                    marketId: WETH_USDC_MARKET_ID,
                    triggerLtv: triggerLtv,
                    maxTopUpAssets: 10 ether // 10 WETH
                })
            )
        );

        PolicyManager.PolicyBinding memory binding = _buildBinding(MORPHO_WETH_LOAN_PROTECTION_POLICY, policyConfig, 0);
        bytes32 policyId = POLICY_MANAGER.getPolicyId(binding);

        vm.expectEmit(true, true, true, false);
        emit PolicyManager.PolicyInstalled(policyId, account, MORPHO_WETH_LOAN_PROTECTION_POLICY);

        vm.prank(account);
        POLICY_MANAGER.install(binding);

        assertTrue(POLICY_MANAGER.isPolicyInstalled(MORPHO_WETH_LOAN_PROTECTION_POLICY, policyId));
        console2.log("MorphoWethLoanProtectionPolicy installed, policyId:", vm.toString(policyId));
    }

    ////////////////////////////////////////////////////////////////
    ///                       Helpers                            ///
    ////////////////////////////////////////////////////////////////

    function _buildBinding(address policy, bytes memory policyConfig, uint256 salt)
        internal
        view
        returns (PolicyManager.PolicyBinding memory)
    {
        return PolicyManager.PolicyBinding({
            account: account, policy: policy, policyConfig: policyConfig, validAfter: 0, validUntil: 0, salt: salt
        });
    }
}
