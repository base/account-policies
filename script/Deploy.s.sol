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
 * forge script script/Deploy.s.sol:Deploy --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 */
contract Deploy is Script {
    /// @notice Deploys the core protocol contracts and MorphoLendPolicy.
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    /// @notice Deploys the PublicERC6492Validator, PolicyManager, and MorphoLendPolicy.
    ///
    /// @dev Reads `ADMIN` from the environment for the MorphoLendPolicy admin role.
    ///
    /// @return validator Deployed ERC-6492 validator.
    /// @return policyManager Deployed policy manager.
    /// @return morphoLendPolicy Deployed Morpho lend policy.
    function deploy()
        internal
        returns (PublicERC6492Validator validator, PolicyManager policyManager, MorphoLendPolicy morphoLendPolicy)
    {
        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        morphoLendPolicy = new MorphoLendPolicy(address(policyManager), vm.envAddress("ADMIN"));

        logAddress("PublicERC6492Validator", address(validator));
        logAddress("PolicyManager", address(policyManager));
        logAddress("MorphoLendPolicy", address(morphoLendPolicy));
    }

    /// @notice Logs a deployed contract address.
    ///
    /// @param name Human-readable label.
    /// @param addr Contract address.
    function logAddress(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}

