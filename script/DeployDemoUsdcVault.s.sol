// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {MockMorphoVault} from "../test/mocks/MockMorpho.sol";

/**
 * @notice Deploy a demo vault (MockMorphoVault) using an existing USDC token.
 *
 * Example:
 * export USDC_ADDR=0x...
 * forge script script/DeployDemoUsdcVault.s.sol:DeployDemoUsdcVault --account dev --sender $SENDER --rpc-url $RPC --broadcast -vvvv
 */
contract DeployDemoUsdcVault is Script {
    function run() external returns (address vault) {
        address usdc = vm.envAddress("USDC_ADDR");

        vm.startBroadcast();
        vault = address(new MockMorphoVault(usdc));
        vm.stopBroadcast();

        console2.log("USDC", usdc);
        console2.log("MockMorphoVault", vault);
    }
}

