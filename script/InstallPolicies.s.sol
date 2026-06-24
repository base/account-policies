// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PolicyManager} from "../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../src/policies/MorphoLendPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../src/policies/MorphoLoanProtectionPolicy.sol";
import {SingleExecutorPolicy} from "../src/policies/SingleExecutorPolicy.sol";

import {Id, MarketParams} from "../src/interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../src/interfaces/morpho/IMorphoBlue.sol";

/// @title InstallPolicies
///
/// @notice Broadcast script that sends real `installWithSignature()` transactions on Base mainnet to trigger
///         `PolicyInstalled` events for each of the 3 active policies.
///
/// @dev Each run generates a fresh random keypair for the user account. The user signs EIP-712 install digests
///      offchain (via `vm.sign`), and the deployer relays the installations via `installWithSignature`. This
///      avoids the one-active-policy-per-market constraint by using a unique account each run.
///
///      Required env:
///        DEPLOYER_PK       — private key for the relayer EOA (pays gas)
///        DEPLOYER_ADDRESS  — corresponding address (also used as executor in policy configs)
///
///      Example:
///        source .env && forge script script/InstallPolicies.s.sol:InstallPolicies \
///          --rpc-url $BASE_RPC --broadcast -vvvv
contract InstallPolicies is Script {
    ////////////////////////////////////////////////////////////////
    ///                      Constants                           ///
    ////////////////////////////////////////////////////////////////

    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

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

    /// @dev cbBTC/USDC market (cbBTC collateral, USDC loan). lltv = 86%.
    Id constant CBBTC_USDC_MARKET_ID = Id.wrap(0x9103c3b4e834476c9a62ea009ba2c884ee42e94e6e314a26f04d312434191836);

    /// @dev WETH/USDC market (WETH collateral, USDC loan). lltv = 86%.
    Id constant WETH_USDC_MARKET_ID = Id.wrap(0x8793cf302b8ffd655ab97bd1c695dbd967807e8367a65cb2f4edaf1380ba1bda);

    ////////////////////////////////////////////////////////////////
    ///                        Script                            ///
    ////////////////////////////////////////////////////////////////

    function run() public {
        uint256 deployerPk = vm.envUint("DEPLOYER_PK");
        address executor = vm.envAddress("DEPLOYER_ADDRESS");

        // Generate a fresh random keypair for the user account.
        // Each run gets a unique account, avoiding one-active-policy-per-market collisions.
        uint256 userPk = uint256(keccak256(abi.encode(block.timestamp, block.prevrandao, "install-user")));
        address user = vm.addr(userPk);

        // Salt doesn't need to vary across runs since the account itself is unique, but we include
        // block.timestamp for additional uniqueness if the same keypair is ever reused.
        uint256 salt = vm.envOr("SALT", block.timestamp);

        console2.log("User (binding.account):", user);
        console2.log("Executor/Relayer:", executor);
        console2.log("Salt:", salt);
        console2.log("");

        vm.startBroadcast(deployerPk);

        _installWithSig(MORPHO_LEND_POLICY, _morphoLendConfig(executor), user, userPk, salt, "MorphoLendPolicy");
        _installWithSig(
            MORPHO_LOAN_PROTECTION_POLICY,
            _morphoLoanProtectionConfig(executor),
            user,
            userPk,
            salt,
            "MorphoLoanProtectionPolicy"
        );
        _installWithSig(
            MORPHO_WETH_LOAN_PROTECTION_POLICY,
            _morphoWethLoanProtectionConfig(executor),
            user,
            userPk,
            salt,
            "MorphoWethLoanProtectionPolicy"
        );

        vm.stopBroadcast();
    }

    ////////////////////////////////////////////////////////////////
    ///                   Internal Helpers                       ///
    ////////////////////////////////////////////////////////////////

    /// @dev Builds the binding, signs the install digest with the user's key, and relays via installWithSignature.
    function _installWithSig(
        address policy,
        bytes memory policyConfig,
        address user,
        uint256 userPk,
        uint256 salt,
        string memory label
    ) internal {
        PolicyManager.PolicyBinding memory binding = _buildBinding(user, policy, policyConfig, salt);
        bytes32 policyId = POLICY_MANAGER.getPolicyId(binding);

        // Sign the EIP-712 install digest as the user.
        uint256 deadline = 0; // no expiry
        bytes32 structHash = keccak256(abi.encode(POLICY_MANAGER.INSTALL_POLICY_TYPEHASH(), policyId, deadline));
        bytes32 digest = _hashTypedData(address(POLICY_MANAGER), structHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Relay the installation — deployer is msg.sender, user authorized via signature.
        POLICY_MANAGER.installWithSignature(binding, signature, deadline, "");

        console2.log(string.concat(label, " installed, policyId:"), vm.toString(policyId));
    }

    /// @dev Computes the EIP-712 typed data hash for the PolicyManager domain.
    function _hashTypedData(address verifyingContract, bytes32 structHash) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("Policy Manager"), keccak256("1"), block.chainid, verifyingContract)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    ////////////////////////////////////////////////////////////////
    ///                  Policy Configs                          ///
    ////////////////////////////////////////////////////////////////

    function _morphoLendConfig(address executor) internal pure returns (bytes memory) {
        return abi.encode(
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
    }

    function _morphoLoanProtectionConfig(address executor) internal view returns (bytes memory) {
        MarketParams memory marketParams = MORPHO_BLUE.idToMarketParams(CBBTC_USDC_MARKET_ID);
        return abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor}),
            abi.encode(
                MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                    marketId: CBBTC_USDC_MARKET_ID,
                    triggerLtv: marketParams.lltv / 2, // 50% of lltv
                    maxTopUpAssets: 1e8 // 1 cbBTC (8 decimals)
                })
            )
        );
    }

    function _morphoWethLoanProtectionConfig(address executor) internal view returns (bytes memory) {
        MarketParams memory marketParams = MORPHO_BLUE.idToMarketParams(WETH_USDC_MARKET_ID);
        return abi.encode(
            SingleExecutorPolicy.SingleExecutorConfig({executor: executor}),
            abi.encode(
                MorphoLoanProtectionPolicy.LoanProtectionPolicyConfig({
                    marketId: WETH_USDC_MARKET_ID,
                    triggerLtv: marketParams.lltv / 2, // 50% of lltv
                    maxTopUpAssets: 10 ether // 10 WETH
                })
            )
        );
    }

    function _buildBinding(address account, address policy, bytes memory policyConfig, uint256 salt)
        internal
        pure
        returns (PolicyManager.PolicyBinding memory)
    {
        return PolicyManager.PolicyBinding({
            account: account, policy: policy, policyConfig: policyConfig, validAfter: 0, validUntil: 0, salt: salt
        });
    }
}
