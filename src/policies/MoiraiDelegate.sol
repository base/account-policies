// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {
    ECDSA
} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {AOAPolicy} from "./AOAPolicy.sol";

/// @title MoiraiDelegate
///
/// @notice AOA policy for delegating a wallet owner staged onchain action, gated by a timelock
///         and/or a consensus co-signer.
///
/// @dev Properties:
///      - fixed target, value, and callData pinned in policyConfig
///      - optional timelock: execution blocked until `block.timestamp >= unlockTimestamp`
///      - optional consensus signer: each execution requires a valid EOA signature from `consensusSigner`
///        over the canonical policy-approval digest for this instance
///      - at least one condition must be specified at install time
///      - executor-signed execution intents (AOA standard)
///
///      The consensus signer approves by signing a digest that binds to the specific policy instance
///      (`policyId`), the associated `account`, and the committed config hash — preventing a signature
///      intended for one instance from authorizing execution on a different instance.
///
///      Install and uninstall must be authorized by the wallet owner (enforced by `PolicyManager`).
contract MoiraiDelegate is AOAPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy-specific config for a delegated onchain action.
    struct DelegateConfig {
        /// @dev Contract to call on execution.
        address target;
        /// @dev ETH value forwarded with the call.
        uint256 value;
        /// @dev Calldata forwarded to `target`.
        bytes callData;
        /// @dev Earliest timestamp (seconds) at which execution is allowed. Zero means no timelock.
        uint256 unlockTimestamp;
        /// @dev EOA required to co-approve each execution. address(0) means no consensus required.
        address consensusSigner;
    }

    /// @notice Policy-specific action data for each execution.
    struct DelegateExecution {
        /// @dev Consensus signer's EOA signature over the canonical approval digest for this
        ///      policy instance. Must be non-empty when a `consensusSigner` is configured.
        bytes consensusSignature;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice EIP-712 typehash for consensus signer approval.
    ///
    /// @dev The approval commits to the specific policy instance, associated account, and committed
    ///      config hash, preventing cross-instance replay.
    bytes32 public constant CONSENSUS_APPROVAL_TYPEHASH =
        keccak256(
            "ConsensusApproval(bytes32 policyId,address account,bytes32 policyConfigHash)"
        );

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when the policy is installed with neither a timelock nor a consensus signer.
    error NoConditionSpecified();

    /// @notice Thrown when executing before the configured unlock timestamp.
    ///
    /// @param currentTimestamp Current block timestamp in seconds.
    /// @param unlockTimestamp Configured unlock timestamp in seconds.
    error TimelockNotMet(uint256 currentTimestamp, uint256 unlockTimestamp);

    /// @notice Thrown when the consensus signature does not recover to the configured signer.
    error InvalidConsensusSignature();

    /// @notice Thrown when the target address in the policy config is zero.
    error ZeroTarget();

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` (controls pause/unpause).
    constructor(
        address policyManager,
        address admin
    ) AOAPolicy(policyManager, admin) {}

    ////////////////////////////////////////////////////////////////
    ///                 External View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Computes the EIP-712 digest a consensus signer must sign to approve a policy instance.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param policyConfig Full config preimage bytes (hash must match the stored config hash).
    ///
    /// @return Digest the consensus signer should sign with their EOA key.
    function getConsensusApprovalDigest(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig
    ) external view returns (bytes32) {
        _requireConfigHash(policyId, policyConfig);
        return
            _consensusDigest(
                policyId,
                account,
                _configHashByPolicyId[policyId]
            );
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Validates that the delegate config specifies at least one condition and a non-zero target.
    function _onAOAInstall(
        bytes32,
        address,
        AOAConfig memory,
        bytes memory policySpecificConfig
    ) internal override {
        DelegateConfig memory cfg = abi.decode(
            policySpecificConfig,
            (DelegateConfig)
        );
        if (cfg.target == address(0)) revert ZeroTarget();
        if (cfg.unlockTimestamp == 0 && cfg.consensusSigner == address(0)) {
            revert NoConditionSpecified();
        }
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Verifies all configured conditions, then returns the account call plan using the pinned config.
    ///
    /// Condition evaluation order:
    /// 1. Timelock (if configured): `block.timestamp >= unlockTimestamp`
    /// 2. Consensus signature (if configured): ECDSA recovery matches `consensusSigner`
    function _onAOAExecute(
        bytes32 policyId,
        address account,
        AOAConfig memory,
        bytes memory policySpecificConfig,
        bytes memory actionData
    )
        internal
        override
        returns (bytes memory accountCallData, bytes memory postCallData)
    {
        DelegateConfig memory cfg = abi.decode(
            policySpecificConfig,
            (DelegateConfig)
        );
        DelegateExecution memory exec = abi.decode(
            actionData,
            (DelegateExecution)
        );

        if (cfg.unlockTimestamp != 0 && block.timestamp < cfg.unlockTimestamp) {
            revert TimelockNotMet(block.timestamp, cfg.unlockTimestamp);
        }

        if (cfg.consensusSigner != address(0)) {
            _requireConsensusSignature(
                policyId,
                account,
                cfg.consensusSigner,
                exec.consensusSignature
            );
        }

        accountCallData = abi.encodeCall(
            CoinbaseSmartWallet.execute,
            (cfg.target, cfg.value, cfg.callData)
        );
        postCallData = "";
    }

    /// @dev EIP-712 domain name and version for this policy.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "Moirai Delegate";
        version = "1";
    }

    ////////////////////////////////////////////////////////////////
    ///                   Private Functions                      ///
    ////////////////////////////////////////////////////////////////

    /// @dev Verifies that `signature` recovers to `consensusSigner` over the canonical approval digest.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param consensusSigner Expected EOA signer address.
    /// @param signature ECDSA signature bytes (65 bytes: r || s || v).
    function _requireConsensusSignature(
        bytes32 policyId,
        address account,
        address consensusSigner,
        bytes memory signature
    ) private view {
        bytes32 digest = _consensusDigest(
            policyId,
            account,
            _configHashByPolicyId[policyId]
        );
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(
            digest,
            signature
        );
        if (err != ECDSA.RecoverError.NoError || recovered != consensusSigner) {
            revert InvalidConsensusSignature();
        }
    }

    /// @dev Computes the EIP-712 consensus approval digest.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param configHash Stored config hash for the policyId.
    ///
    /// @return EIP-712 digest the consensus signer must sign.
    function _consensusDigest(
        bytes32 policyId,
        address account,
        bytes32 configHash
    ) private view returns (bytes32) {
        return
            _hashTypedData(
                keccak256(
                    abi.encode(
                        CONSENSUS_APPROVAL_TYPEHASH,
                        policyId,
                        account,
                        configHash
                    )
                )
            );
    }
}
