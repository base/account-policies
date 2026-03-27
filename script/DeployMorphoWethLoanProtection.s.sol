// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {MorphoWethLoanProtectionPolicy} from "../src/policies/MorphoWethLoanProtectionPolicy.sol";

/**
 * @notice Deploy a `MorphoWethLoanProtectionPolicy` against an existing `PolicyManager`.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Required env:
 *   ADMIN          — admin address for policy roles
 *   POLICY_MANAGER — address of the already-deployed PolicyManager
 *   WETH           — WETH contract address for the target chain
 *                    Base:    0x4200000000000000000000000000000000000006
 *                    Mainnet: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
 *
 * Example (Base):
 *   ADMIN=$ADMIN POLICY_MANAGER=$PM WETH=0x4200000000000000000000000000000000000006 \
 *   forge script script/DeployMorphoWethLoanProtection.s.sol:DeployMorphoWethLoanProtection \
 *     --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 */
contract DeployMorphoWethLoanProtection is Script {
    /// @dev Morpho Blue singleton (same address on all supported chains).
    address internal constant MORPHO_BLUE = 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;

    /// @notice Deploys a `MorphoWethLoanProtectionPolicy` connected to an existing PolicyManager.
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    /// @notice Deploys the WETH loan protection policy.
    ///
    /// @dev Reads `ADMIN`, `POLICY_MANAGER`, and `WETH` from the environment.
    ///
    /// @return policy Deployed WETH loan protection policy.
    function deploy() internal returns (MorphoWethLoanProtectionPolicy policy) {
        address admin = vm.envAddress("ADMIN");
        address policyManager = vm.envAddress("POLICY_MANAGER");
        address weth = vm.envAddress("WETH");

        policy = new MorphoWethLoanProtectionPolicy(policyManager, admin, MORPHO_BLUE, weth);

        console2.log("MorphoWethLoanProtectionPolicy", address(policy));
    }
}
