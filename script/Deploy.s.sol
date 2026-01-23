// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../src/policies/MorphoLendPolicy.sol";

/**
 * @notice Deploy the core protocol + MorphoLendPolicy.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Example:
 * forge script script/Deploy.s.sol:Deploy --account dev --sender $SENDER --rpc-url $RPC --broadcast -vvvv
 */
contract Deploy is Script {
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    function deploy()
        internal
        returns (PublicERC6492Validator validator, PolicyManager policyManager, MorphoLendPolicy morphoLendPolicy)
    {
        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        morphoLendPolicy = new MorphoLendPolicy(address(policyManager));

        logAddress("PublicERC6492Validator", address(validator));
        logAddress("PolicyManager", address(policyManager));
        logAddress("MorphoLendPolicy", address(morphoLendPolicy));
    }

    function logAddress(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}

