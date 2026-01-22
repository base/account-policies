// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PublicERC6492Validator} from "../PublicERC6492Validator.sol";
import {PolicyTypes} from "../PolicyTypes.sol";
import {Policy} from "./Policy.sol";

interface IAOAPolicyManagerLike {
    function PUBLIC_ERC6492_VALIDATOR() external view returns (PublicERC6492Validator);
}

/// @notice Template-method base for "Automated On-chain Actions" (AOA) policies.
/// @dev Enforces canonical ABI encoding shapes by owning the external entrypoints:
///      - policyConfig = abi.encode(AOAConfig{account,executor}, bytes policySpecificConfig)
///      - policyData   = abi.encode(bytes actionData, bytes signature)
abstract contract AOAPolicy is Policy {
    struct AOAConfig {
        address account;
        address executor;
    }

    error InvalidSender(address sender, address expected);
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error InvalidAOAConfigAccount(address actual, address expected);
    error ZeroExecutor();

    address public immutable POLICY_MANAGER;

    modifier requireSender(address sender) {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
        _;
    }

    constructor(address policyManager) {
        POLICY_MANAGER = policyManager;
    }

    function onInstall(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId, bytes calldata policyConfig)
        external
        override
        requireSender(POLICY_MANAGER)
    {
        _checkPolicyConfigHash(binding.policyConfigHash, policyConfig);
        (AOAConfig memory aoa, bytes memory policySpecificConfig) = abi.decode(policyConfig, (AOAConfig, bytes));
        _validateAOAConfigAccount(aoa, binding.account);
        _onAOAInstall(binding, policyId, aoa, policySpecificConfig);
    }

    function onRevoke(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId)
        external
        override
        requireSender(POLICY_MANAGER)
    {
        _onAOARevoke(binding, policyId);
    }

    function onExecute(
        PolicyTypes.PolicyBinding calldata binding,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    )
        external
        override
        requireSender(POLICY_MANAGER)
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        _checkPolicyConfigHash(binding.policyConfigHash, policyConfig);

        // If the child policy does not encode config with the AOA prefix first, this decode will revert.
        (AOAConfig memory aoa, bytes memory policySpecificConfig) = abi.decode(policyConfig, (AOAConfig, bytes));
        _validateAOAConfigAccount(aoa, binding.account);

        // If the child policy does not encode policyData as (bytes actionData, bytes signature), this decode will revert.
        (bytes memory actionData, bytes memory signature) = abi.decode(policyData, (bytes, bytes));

        return _onAOAExecute(binding, aoa, policySpecificConfig, actionData, signature, caller);
    }

    function _onAOAInstall(
        PolicyTypes.PolicyBinding calldata binding,
        bytes32 policyId,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig
    ) internal virtual {
        binding;
        policyId;
        aoa;
        policySpecificConfig;
    }

    function _onAOARevoke(PolicyTypes.PolicyBinding calldata binding, bytes32 policyId) internal virtual {
        binding;
        policyId;
    }

    function _onAOAExecute(
        PolicyTypes.PolicyBinding calldata binding,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);

    function _validateAOAConfigAccount(AOAConfig memory aoa, address expectedAccount) internal pure {
        if (aoa.account != expectedAccount) revert InvalidAOAConfigAccount(aoa.account, expectedAccount);
        if (aoa.executor == address(0)) revert ZeroExecutor();
    }

    function _checkPolicyConfigHash(bytes32 expected, bytes calldata policyConfig) internal pure {
        bytes32 actual = keccak256(policyConfig);
        if (actual != expected) revert PolicyConfigHashMismatch(actual, expected);
    }

    function _isValidExecutorSig(address executor, bytes32 digest, bytes memory signature) internal returns (bool) {
        return IAOAPolicyManagerLike(POLICY_MANAGER).PUBLIC_ERC6492_VALIDATOR().isValidSignatureNowAllowSideEffects(
            executor, digest, signature
        );
    }
}

