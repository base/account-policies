// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {MockMorphoVault} from "../test/lib/mocks/MockMorpho.sol";

/**
 * @notice Deploy a demo vault (MockMorphoVault) using an existing USDC token.
 *
 * Example:
 * export USDC_ADDR=0x...
 * forge script script/DeployDemoUsdcVault.s.sol:DeployDemoUsdcVault --account dev --sender $SENDER --rpc-url $RPC --broadcast -vvvv
 */
contract DeployDemoUsdcVault is Script {
    /// @notice Deploys a `MockMorphoVault` for an existing USDC token.
    ///
    /// @dev Reads `USDC_ADDR` from the environment.
    ///
    /// @return vault Deployed vault address.
    function run() external returns (address vault) {
        address usdc = vm.envAddress("USDC_ADDR");

        vm.startBroadcast();
        vault = address(new MockMorphoVault(usdc));
        vm.stopBroadcast();

        console2.log("USDC", usdc);
        console2.log("MockMorphoVault", vault);
    }
}

