// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {MoiraiDelegate} from "../src/policies/MoiraiDelegate.sol";

/**
 * @notice Deploy MoiraiDelegate with or without the core protocol.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Deploy policy only against an existing manager (default):
 * export POLICY_MANAGER=0x...
 * forge script script/DeployMoiraiDelegate.s.sol:DeployMoiraiDelegate --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 *
 * Deploy full stack (validator + manager + policy):
 * forge script script/DeployMoiraiDelegate.s.sol:DeployMoiraiDelegate --sig "runAll()" --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 */
contract DeployMoiraiDelegate is Script {
    /// @notice Deploys MoiraiDelegate against an existing PolicyManager.
    ///
    /// @dev Reads `POLICY_MANAGER` and `ADMIN` from the environment.
    function run() public {
        vm.startBroadcast();
        deployPolicyOnly(vm.envAddress("POLICY_MANAGER"));
        vm.stopBroadcast();
    }

    /// @notice Deploys the full protocol stack and MoiraiDelegate.
    ///
    /// @dev Reads `ADMIN` from the environment.
    function runAll() public {
        vm.startBroadcast();
        deployAll();
        vm.stopBroadcast();
    }

    /// @notice Deploys `PublicERC6492Validator`, `PolicyManager`, and `MoiraiDelegate`.
    ///
    /// @dev Reads `ADMIN` from the environment for the policy admin role.
    ///
    /// @return validator Deployed ERC-6492 validator.
    /// @return policyManager Deployed policy manager.
    /// @return moiraiDelegate Deployed MoiraiDelegate policy.
    function deployAll()
        internal
        returns (PublicERC6492Validator validator, PolicyManager policyManager, MoiraiDelegate moiraiDelegate)
    {
        address admin = vm.envAddress("ADMIN");

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        moiraiDelegate = new MoiraiDelegate(address(policyManager), admin);

        logAddress("PublicERC6492Validator", address(validator));
        logAddress("PolicyManager", address(policyManager));
        logAddress("MoiraiDelegate", address(moiraiDelegate));
    }

    /// @notice Deploys `MoiraiDelegate` against an existing `PolicyManager`.
    ///
    /// @dev Reads `ADMIN` from the environment for the policy admin role.
    ///
    /// @param policyManager Address of the existing `PolicyManager`.
    ///
    /// @return moiraiDelegate Deployed MoiraiDelegate policy.
    function deployPolicyOnly(address policyManager) internal returns (MoiraiDelegate moiraiDelegate) {
        address admin = vm.envAddress("ADMIN");

        moiraiDelegate = new MoiraiDelegate(policyManager, admin);

        logAddress("MoiraiDelegate", address(moiraiDelegate));
    }

    /// @notice Logs a deployed contract address.
    ///
    /// @param name Human-readable label.
    /// @param addr Contract address.
    function logAddress(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}
