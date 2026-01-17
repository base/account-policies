// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ReentrancyGuard} from "openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {PublicERC6492Validator} from "./PublicERC6492Validator.sol";
import {PolicyTypes} from "./PolicyTypes.sol";
import {Policy} from "./policies/Policy.sol";

/// @title PolicyManager
/// @notice Wallet-agnostic module that installs policies authorized by the account and executes policy-prepared
///         calldata on the account.
contract PolicyManager is EIP712, ReentrancyGuard {
    /// @notice Separated contract for validating signatures and executing ERC-6492 side effects.
    PublicERC6492Validator public immutable PUBLIC_ERC6492_VALIDATOR;

    /// @notice EIP-712 hash of Install type.
    bytes32 public constant INSTALL_TYPEHASH = keccak256(
        "Install(address account,address policy,bytes32 policyConfigHash,uint48 validAfter,uint48 validUntil,uint256 salt)"
    );

    /// @notice EIP-712 hash of Revoke type.
    bytes32 public constant REVOKE_TYPEHASH = keccak256("Revoke(bytes32 policyId)");

    /// @notice EIP-712 hash of Execution type.
    bytes32 public constant EXECUTION_TYPEHASH = keccak256(
        "Execution(bytes32 policyId,address account,address policy,bytes32 policyConfigHash,bytes32 policyDataHash,uint256 nonce,uint48 deadline)"
    );

    /// @notice Policy was installed.
    event PolicyInstalled(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy was revoked.
    event PolicyRevoked(bytes32 indexed policyId, address indexed account, address indexed policy);

    /// @notice Policy execution occurred.
    event Executed(bytes32 indexed policyId, address indexed account, address indexed policy, uint256 nonce);

    error InvalidSignature();
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error PolicyNotInstalled(bytes32 policyId);
    error PolicyRevokedAlready(bytes32 policyId);
    error PolicyAlreadyInstalled(bytes32 policyId);
    error BeforeValidAfter(uint48 currentTimestamp, uint48 validAfter);
    error AfterValidUntil(uint48 currentTimestamp, uint48 validUntil);
    error DeadlineExceeded(uint48 currentTimestamp, uint48 deadline);
    error AccountCallFailed(address account, bytes returnData);
    error InvalidSender(address sender, address expected);

    struct PolicyState {
        bool installed;
        bool revoked;
    }

    mapping(bytes32 policyId => PolicyState) internal _policyState;
    mapping(bytes32 executionDigest => bool used) internal _usedExecutionDigest;

    modifier requireSender(address sender) {
        _requireSender(sender);
        _;
    }

    function _requireSender(address sender) internal view {
        if (msg.sender != sender) revert InvalidSender(msg.sender, sender);
    }

    constructor(PublicERC6492Validator publicERC6492Validator) {
        PUBLIC_ERC6492_VALIDATOR = publicERC6492Validator;
    }

    /// @notice Install a policy via a signature from the account.
    /// @dev Compatible with ERC-6492 signatures including side effects.
    function installPolicyWithSignature(
        PolicyTypes.Install calldata install,
        bytes calldata policyConfig,
        bytes calldata userSig
    ) external nonReentrant returns (bytes32 policyId) {
        _checkPolicyConfigHash(install.policyConfigHash, policyConfig);
        _checkInstallWindow(install.validAfter, install.validUntil);

        bytes32 structHash = getInstallStructHash(install);
        policyId = structHash;

        PolicyState storage state = _policyState[policyId];
        if (state.installed) revert PolicyAlreadyInstalled(policyId);
        if (state.revoked) revert PolicyRevokedAlready(policyId);

        bytes32 digest = _hashTypedData(structHash);
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(install.account, digest, userSig)) {
            revert InvalidSignature();
        }

        state.installed = true;
        emit PolicyInstalled(policyId, install.account, install.policy);
    }

    /// @notice Install a policy via a direct call from the account.
    function installPolicy(PolicyTypes.Install calldata install, bytes calldata policyConfig)
        external
        nonReentrant
        requireSender(install.account)
        returns (bytes32 policyId)
    {
        _checkPolicyConfigHash(install.policyConfigHash, policyConfig);
        _checkInstallWindow(install.validAfter, install.validUntil);

        bytes32 structHash = getInstallStructHash(install);
        policyId = structHash;

        PolicyState storage state = _policyState[policyId];
        if (state.installed) revert PolicyAlreadyInstalled(policyId);
        if (state.revoked) revert PolicyRevokedAlready(policyId);

        state.installed = true;
        emit PolicyInstalled(policyId, install.account, install.policy);
    }

    /// @notice Revoke a policy via a signature from the account.
    /// @dev Compatible with ERC-6492 signatures including side effects.
    function revokePolicyWithSignature(
        PolicyTypes.Install calldata install,
        bytes calldata policyConfig,
        bytes calldata userSig
    ) external nonReentrant returns (bytes32 policyId) {
        _checkPolicyConfigHash(install.policyConfigHash, policyConfig);

        bytes32 structHash = getInstallStructHash(install);
        policyId = structHash;

        PolicyState storage state = _policyState[policyId];
        if (!state.installed) revert PolicyNotInstalled(policyId);
        if (state.revoked) revert PolicyRevokedAlready(policyId);

        // IMPORTANT: revoke signatures must be distinct from install signatures to avoid signature replay/ambiguity.
        bytes32 digest = _hashTypedData(getRevokeStructHash(policyId));
        if (!PUBLIC_ERC6492_VALIDATOR.isValidSignatureNowAllowSideEffects(install.account, digest, userSig)) {
            revert InvalidSignature();
        }

        state.revoked = true;
        emit PolicyRevoked(policyId, install.account, install.policy);
    }

    /// @notice Revoke a policy via a direct call from the account.
    function revokePolicy(PolicyTypes.Install calldata install, bytes calldata policyConfig)
        external
        nonReentrant
        requireSender(install.account)
        returns (bytes32 policyId)
    {
        _checkPolicyConfigHash(install.policyConfigHash, policyConfig);

        bytes32 structHash = getInstallStructHash(install);
        policyId = structHash;

        PolicyState storage state = _policyState[policyId];
        if (!state.installed) revert PolicyNotInstalled(policyId);
        if (state.revoked) revert PolicyRevokedAlready(policyId);

        state.revoked = true;
        emit PolicyRevoked(policyId, install.account, install.policy);
    }

    /// @notice Execute an action for an installed policy instance.
    /// @dev Policy defines authorization semantics and returns wallet-specific calldata for the account.
    function execute(
        PolicyTypes.Install calldata install,
        bytes calldata policyConfig,
        bytes calldata policyData,
        uint256 execNonce,
        uint48 deadline,
        bytes calldata authorizationData
    ) external nonReentrant {
        _checkPolicyConfigHash(install.policyConfigHash, policyConfig);
        _checkInstallWindow(install.validAfter, install.validUntil);
        _checkDeadline(deadline);

        bytes32 policyId = getInstallStructHash(install);
        _getActivePolicyState(policyId);

        bytes32 execDigest = _getExecutionDigest(policyId, install, keccak256(policyData), execNonce, deadline);

        if (_usedExecutionDigest[execDigest]) revert InvalidSignature();
        _usedExecutionDigest[execDigest] = true;

        Policy(install.policy).authorize(install, execNonce, policyConfig, policyData, execDigest, msg.sender, authorizationData);

        (bytes memory accountCallData, bytes memory postCallData) =
            _policyOnExecute(install.policy, install, execNonce, policyConfig, policyData);
        _callAccount(install.account, accountCallData);
        _postCallPolicy(install.policy, postCallData);

        emit Executed(policyId, install.account, install.policy, execNonce);
    }

    function getInstallStructHash(PolicyTypes.Install calldata install) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                INSTALL_TYPEHASH,
                install.account,
                install.policy,
                install.policyConfigHash,
                install.validAfter,
                install.validUntil,
                install.salt
            )
        );
    }

    function getRevokeStructHash(bytes32 policyId) public pure returns (bytes32) {
        return keccak256(abi.encode(REVOKE_TYPEHASH, policyId));
    }

    function _checkPolicyConfigHash(bytes32 expected, bytes calldata policyConfig) internal pure {
        bytes32 actual = keccak256(policyConfig);
        if (actual != expected) revert PolicyConfigHashMismatch(actual, expected);
    }

    function _checkInstallWindow(uint48 validAfter, uint48 validUntil) internal view {
        uint48 currentTimestamp = uint48(block.timestamp);
        if (validAfter != 0 && currentTimestamp < validAfter) revert BeforeValidAfter(currentTimestamp, validAfter);
        if (validUntil != 0 && currentTimestamp >= validUntil) revert AfterValidUntil(currentTimestamp, validUntil);
    }

    function _checkDeadline(uint48 deadline) internal view {
        uint48 currentTimestamp = uint48(block.timestamp);
        if (currentTimestamp > deadline) revert DeadlineExceeded(currentTimestamp, deadline);
    }

    function _getActivePolicyState(bytes32 policyId) internal view returns (PolicyState storage state) {
        state = _policyState[policyId];
        if (!state.installed) revert PolicyNotInstalled(policyId);
        if (state.revoked) revert PolicyRevokedAlready(policyId);
    }

    function _getExecutionDigest(
        bytes32 policyId,
        PolicyTypes.Install calldata install,
        bytes32 policyDataHash,
        uint256 nonce,
        uint48 deadline
    ) internal view returns (bytes32) {
        return _hashTypedData(
            keccak256(
                abi.encode(
                    EXECUTION_TYPEHASH,
                    policyId,
                    install.account,
                    install.policy,
                    install.policyConfigHash,
                    policyDataHash,
                    nonce,
                    deadline
                )
            )
        );
    }

    function _callAccount(address account, bytes memory accountCallData) internal {
        (bool success, bytes memory returnData) = account.call(accountCallData);
        if (!success) revert AccountCallFailed(account, returnData);
    }

    function _policyOnExecute(
        address policy,
        PolicyTypes.Install calldata install,
        uint256 execNonce,
        bytes calldata policyConfig,
        bytes calldata policyData
    ) internal returns (bytes memory, bytes memory) {
        (bytes memory accountCallData, bytes memory postCallData) =
            Policy(policy).onExecute(install, execNonce, policyConfig, policyData);
        return (accountCallData, postCallData);
    }

    function _postCallPolicy(address policy, bytes memory postCallData) internal {
        if (postCallData.length == 0) return;
        (bool success, bytes memory returnData) = policy.call(postCallData);
        if (!success) revert AccountCallFailed(policy, returnData);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Policy Manager";
        version = "1";
    }
}

