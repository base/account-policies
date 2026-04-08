// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {MorphoLendPolicy} from "../src/policies/MorphoLendPolicy.sol";
import {MorphoLoanProtectionPolicy} from "../src/policies/MorphoLoanProtectionPolicy.sol";
import {MorphoWethLoanProtectionPolicy} from "../src/policies/MorphoWethLoanProtectionPolicy.sol";

/**
 * @notice Deploy the core protocol + Morpho policies.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Required env:
 *   ADMIN          — admin address for policy roles
 *   WETH           — WETH contract address for the target chain
 *                     Base:    0x4200000000000000000000000000000000000006
 *                     Mainnet: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
 *   MAX_TRIGGER_LTV_RATIO — max allowed ratio of triggerLtv to lltv (WAD-scaled, e.g. 950000000000000000 = 95%)
 *
 * Example (Base):
 *   ADMIN=$ADMIN WETH=0x4200000000000000000000000000000000000006 \
 *   forge script script/Deploy.s.sol:Deploy --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
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

    /// @notice Deploys the full protocol: validator, manager, and all Morpho policies.
    ///
    /// @dev Reads `ADMIN` and `WETH` from the environment.
    ///
    /// @return validator Deployed ERC-6492 validator.
    /// @return policyManager Deployed policy manager.
    /// @return morphoLendPolicy Deployed Morpho lend policy.
    /// @return morphoLoanProtectionPolicy Deployed Morpho loan protection policy.
    /// @return morphoWethLoanProtectionPolicy Deployed Morpho WETH loan protection policy.
    function deploy()
        internal
        returns (
            PublicERC6492Validator validator,
            PolicyManager policyManager,
            MorphoLendPolicy morphoLendPolicy,
            MorphoLoanProtectionPolicy morphoLoanProtectionPolicy,
            MorphoWethLoanProtectionPolicy morphoWethLoanProtectionPolicy
        )
    {
        address admin = vm.envAddress("ADMIN");
        address weth = vm.envAddress("WETH");
        uint256 maxTriggerLtvRatio = vm.envUint("MAX_TRIGGER_LTV_RATIO");

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        morphoLendPolicy = new MorphoLendPolicy(address(policyManager), admin);
        morphoLoanProtectionPolicy =
            new MorphoLoanProtectionPolicy(address(policyManager), admin, MORPHO_BLUE, maxTriggerLtvRatio);
        morphoWethLoanProtectionPolicy =
            new MorphoWethLoanProtectionPolicy(address(policyManager), admin, MORPHO_BLUE, weth, maxTriggerLtvRatio);

        logAddress("PublicERC6492Validator", address(validator));
        logAddress("PolicyManager", address(policyManager));
        logAddress("MorphoLendPolicy", address(morphoLendPolicy));
        logAddress("MorphoLoanProtectionPolicy", address(morphoLoanProtectionPolicy));
        logAddress("MorphoWethLoanProtectionPolicy", address(morphoWethLoanProtectionPolicy));
    }

    /// @notice Logs a deployed contract address.
    ///
    /// @param name Human-readable label.
    /// @param addr Contract address.
    function logAddress(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}
