// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../src/policies/MorphoLendPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../src/policies/MorphoLoanProtectionPolicy.sol";

/**
 * @notice Deploy the core protocol + Morpho policies.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Example:
 * forge script script/Deploy.s.sol:Deploy --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 */
contract Deploy is Script {
    /// @dev Morpho Blue singleton (same address on all supported chains).
    address internal constant MORPHO_BLUE = 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb;

    /// @notice Deploys the core protocol contracts and Morpho policies.
    function run() public {
        vm.startBroadcast();
        deploy();
        vm.stopBroadcast();
    }

    /// @notice Deploys the PublicERC6492Validator, PolicyManager, MorphoLendPolicy, and MorphoLoanProtectionPolicy.
    ///
    /// @dev Reads `ADMIN` from the environment for policy admin roles.
    ///
    /// @return validator Deployed ERC-6492 validator.
    /// @return policyManager Deployed policy manager.
    /// @return morphoLendPolicy Deployed Morpho lend policy.
    /// @return morphoLoanProtectionPolicy Deployed Morpho loan protection policy.
    function deploy()
        internal
        returns (
            PublicERC6492Validator validator,
            PolicyManager policyManager,
            MorphoLendPolicy morphoLendPolicy,
            MorphoLoanProtectionPolicy morphoLoanProtectionPolicy
        )
    {
        address admin = vm.envAddress("ADMIN");

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        morphoLendPolicy = new MorphoLendPolicy(address(policyManager), admin);
        morphoLoanProtectionPolicy = new MorphoLoanProtectionPolicy(address(policyManager), admin, MORPHO_BLUE);

        logAddress("PublicERC6492Validator", address(validator));
        logAddress("PolicyManager", address(policyManager));
        logAddress("MorphoLendPolicy", address(morphoLendPolicy));
        logAddress("MorphoLoanProtectionPolicy", address(morphoLoanProtectionPolicy));
    }

    /// @notice Logs a deployed contract address.
    ///
    /// @param name Human-readable label.
    /// @param addr Contract address.
    function logAddress(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}
