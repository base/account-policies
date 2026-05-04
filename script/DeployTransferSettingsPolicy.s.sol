// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Script, console2} from "forge-std/Script.sol";

import {PublicERC6492Validator} from "../src/PublicERC6492Validator.sol";
import {PolicyManager} from "../src/PolicyManager.sol";
import {TransferSettingsPolicy} from "../src/policies/TransferSettingsPolicy.sol";

/**
 * @notice Deploy TransferSettingsPolicy with or without the core protocol.
 *
 * @dev Uses Foundry keystore via `--account`/`--sender`.
 *
 * Deploy policy only against an existing manager (default):
 * export POLICY_MANAGER=0x...
 * forge script script/DeployTransferSettingsPolicy.s.sol:DeployTransferSettingsPolicy --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 *
 * Deploy full stack (validator + manager + policy):
 * forge script script/DeployTransferSettingsPolicy.s.sol:DeployTransferSettingsPolicy --sig "runAll()" --account dev --sender $SENDER --rpc-url $BASE_RPC --verify --broadcast -vvvv
 */
contract DeployTransferSettingsPolicy is Script {
    /// @notice Deploys TransferSettingsPolicy against an existing PolicyManager.
    ///
    /// @dev Reads `POLICY_MANAGER` and `ADMIN` from the environment.
    function run() public {
        vm.startBroadcast();
        deployPolicyOnly(vm.envAddress("POLICY_MANAGER"));
        vm.stopBroadcast();
    }

    /// @notice Deploys the full protocol stack and TransferSettingsPolicy.
    ///
    /// @dev Reads `ADMIN` from the environment.
    function runAll() public {
        vm.startBroadcast();
        deployAll();
        vm.stopBroadcast();
    }

    /// @notice Deploys `PublicERC6492Validator`, `PolicyManager`, and `TransferSettingsPolicy`.
    ///
    /// @dev Reads `ADMIN` from the environment for the policy admin role.
    ///
    /// @return validator Deployed ERC-6492 validator.
    /// @return policyManager Deployed policy manager.
    /// @return policy Deployed TransferSettingsPolicy.
    function deployAll()
        internal
        returns (PublicERC6492Validator validator, PolicyManager policyManager, TransferSettingsPolicy policy)
    {
        address admin = vm.envAddress("ADMIN");

        validator = new PublicERC6492Validator();
        policyManager = new PolicyManager(validator);
        policy = new TransferSettingsPolicy(address(policyManager), admin);

        logAddress("PublicERC6492Validator", address(validator));
        logAddress("PolicyManager", address(policyManager));
        logAddress("TransferSettingsPolicy", address(policy));
    }

    /// @notice Deploys `TransferSettingsPolicy` against an existing `PolicyManager`.
    ///
    /// @dev Reads `ADMIN` from the environment for the policy admin role.
    ///
    /// @param policyManager Address of the existing `PolicyManager`.
    ///
    /// @return policy Deployed TransferSettingsPolicy.
    function deployPolicyOnly(address policyManager) internal returns (TransferSettingsPolicy policy) {
        address admin = vm.envAddress("ADMIN");

        policy = new TransferSettingsPolicy(policyManager, admin);

        logAddress("TransferSettingsPolicy", address(policy));
    }

    /// @notice Logs a deployed contract address.
    ///
    /// @param name Human-readable label.
    /// @param addr Contract address.
    function logAddress(string memory name, address addr) internal pure {
        console2.log(name, addr);
    }
}
