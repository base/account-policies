// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {MoiraiDelegate} from "../src/policies/MoiraiDelegate.sol";

/**
 * @notice Deploy the MoiraiDelegate policy alongside the core protocol.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Required environment variables:
 *   ADMIN   — address granted DEFAULT_ADMIN_ROLE (pause/unpause control)
 *
 * Example (deploy fresh core + policy):
 * forge script script/DeployMoiraiDelegate.s.sol:DeployMoiraiDelegate \
 *   --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 *
 * Example (connect to existing core contracts):
 * POLICY_MANAGER=0x... forge script script/DeployMoiraiDelegate.s.sol:DeployMoiraiDelegateOnly \
 *   --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 */
contract DeployMoiraiDelegate is Script {
    /// @notice Deploys the full protocol stack including `MoiraiDelegate`.
    function run() public {
        vm.startBroadcast();

        address admin = vm.envAddress("ADMIN");

        PublicERC6492Validator validator = new PublicERC6492Validator();
        PolicyManager policyManager = new PolicyManager(validator);
        MoiraiDelegate moiraiDelegate = new MoiraiDelegate(address(policyManager), admin);

        _log("PublicERC6492Validator", address(validator));
        _log("PolicyManager", address(policyManager));
        _log("MoiraiDelegate", address(moiraiDelegate));

        vm.stopBroadcast();
    }

    function _log(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}

/**
 * @notice Deploy only `MoiraiDelegate` against an existing `PolicyManager`.
 *
 * @dev Set POLICY_MANAGER and ADMIN environment variables before running.
 */
contract DeployMoiraiDelegateOnly is Script {
    /// @notice Deploys `MoiraiDelegate` against an existing `PolicyManager`.
    function run() public {
        vm.startBroadcast();

        address policyManager = vm.envAddress("POLICY_MANAGER");
        address admin = vm.envAddress("ADMIN");

        MoiraiDelegate moiraiDelegate = new MoiraiDelegate(policyManager, admin);

        console2.log("MoiraiDelegate", address(moiraiDelegate));

        vm.stopBroadcast();
    }
}
