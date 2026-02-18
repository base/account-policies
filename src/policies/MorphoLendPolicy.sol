// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {IMorphoVault} from "../interfaces/morpho/IMorphoVault.sol";
import {AOAPolicy} from "./AOAPolicy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @title MorphoLendPolicy
///
/// @notice AOA policy that deposits assets into a fixed Morpho vault on behalf of an account.
///
/// @dev Properties:
///      - fixed vault (pinned in config)
///      - fixed receiver (the account)
///      - executor-signed execution intents
///      - recurring allowance bounds on deposited assets (allowance window derived from policy validity window)
contract MorphoLendPolicy is AOAPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Deposit allowance parameters.
    ///
    /// @dev The allowance window bounds (`start`/`end`) are derived from the policy validity window
    ///      (`PolicyManager.policies(policy, policyId).validAfter/validUntil`) to avoid duplicating timestamps in config.
    struct DepositLimitConfig {
        /// @dev Maximum deposits per recurring period window.
        uint160 allowance;
        /// @dev RecurringAllowance.Limit.period length in seconds.
        /// @review prefer to align with uint40 for parity with PolicyManager validAfter/validUntil
        uint48 period;
    }

    /// @notice Policy-specific config for lending into a pinned Morpho vault.
    struct LendPolicyConfig {
        /// @dev Morpho vault to deposit into.
        address vault;
        /// @dev Recurring deposit allowance parameters (window bounds derived from policy validity window).
        DepositLimitConfig depositLimit;
    }

    /// @notice Policy-specific execution payload for deposits.
    struct LendData {
        /// @dev Amount of assets to deposit, in the vault asset token's smallest unit (ERC20 decimals).
        uint256 depositAssets;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Recurring allowance state for deposits.
    RecurringAllowance.State internal _depositLimitState;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when attempting to deposit zero assets.
    error ZeroAmount();

    /// @notice Thrown when the vault address is zero.
    error ZeroVault();

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the policy.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` (controls pause/unpause).
    constructor(address policyManager, address admin) AOAPolicy(policyManager, admin) {}

    ////////////////////////////////////////////////////////////////
    ///                 External View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Return recurring deposit limit usage for a policy instance.
    ///
    /// @dev Requires the config preimage so the contract can decode `depositLimit` without storing it.
    ///
    /// @param policyId Policy identifier for the binding.
    /// @param account Account associated with the policyId.
    /// @param policyConfig Full config preimage bytes.
    ///
    /// @return lastUpdated Last stored period usage snapshot.
    /// @return current Current period usage computed from `depositLimit`.
    function getDepositLimitPeriodUsage(bytes32 policyId, address account, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        _requireConfigHash(policyId, policyConfig);
        (, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);

        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        lastUpdated = RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(
            _depositLimitState, policyId, _addTimeBoundsToDepositLimit(policyId, lendPolicyConfig.depositLimit)
        );
    }

    /// @notice Return the last stored recurring deposit usage for a policy instance.
    ///
    /// @param policyId Policy identifier for the binding.
    ///
    /// @return Last stored period usage snapshot.
    function getDepositLimitLastUpdated(bytes32 policyId)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return RecurringAllowance.getLastUpdated(_depositLimitState, policyId);
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Validates Morpho vault config at install time.
    function _onAOAInstall(bytes32, AOAConfig memory, bytes memory policySpecificConfig) internal override {
        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        if (lendPolicyConfig.vault == address(0)) revert ZeroVault();
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Executes a Morpho vault deposit, enforcing recurring allowance bounds.
    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoaConfig,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        /// @review this was checked on install so do we really need?
        if (lendPolicyConfig.vault == address(0)) revert ZeroVault();

        LendData memory lendData = abi.decode(actionData, (LendData));
        /// @review feels a bit weird to have a struct just for one arg, but I agree I like seeing schemas up top for orientation
        if (lendData.depositAssets == 0) revert ZeroAmount();

        /// @review more comments pls for each code section just for easier skimming
        RecurringAllowance.useLimit(
            _depositLimitState,
            policyId,
            _addTimeBoundsToDepositLimit(policyId, lendPolicyConfig.depositLimit),
            lendData.depositAssets
        );

        /// @review Not sure I like having a separate internal here. Would rather opt to in-line to not have to jump around
        (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender) =
            _buildVaultDepositCall(lendPolicyConfig, aoaConfig.account, lendData.depositAssets);

        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0] = CoinbaseSmartWallet.Call({
            target: approvalToken,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, approvalSpender, lendData.depositAssets)
        });
        calls[1] = CoinbaseSmartWallet.Call({target: target, value: value, data: callData});
        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);

        postCallData = "";
    }

    /// @dev Reads the policy's `validAfter`/`validUntil` timestamps from the PolicyManager and returns them
    ///      as `uint48` bounds suitable for `RecurringAllowance.Limit`. A zero `validUntil` (no expiry) is
    ///      mapped to `type(uint48).max`.
    ///
    /// @param policyId Policy identifier whose validity window is queried.
    ///
    /// @return start Lower bound (inclusive) of the allowance window.
    /// @return end   Upper bound (inclusive) of the allowance window.
    /// @review feels like this function can just be in-lined into the _addTimeBoundsToDepositLimit internal if only used once
    function _getValidityWindowAsLimitBounds(bytes32 policyId) internal view returns (uint48 start, uint48 end) {
        (,,, uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.policies(address(this), policyId);
        start = uint48(validAfter);
        end = validUntil == 0 ? type(uint48).max : uint48(validUntil);
    }

    /// @dev Constructs a full `RecurringAllowance.Limit` by combining the caller-supplied
    ///      `DepositLimitConfig` (allowance, period) with the policy's on-chain validity window
    ///      (start, end) retrieved via `_getValidityWindowAsLimitBounds`.
    ///
    /// @param policyId            Policy identifier used to look up validity timestamps.
    /// @param depositLimitConfig  Allowance and period parameters from the policy config.
    ///
    /// @return depositLimit Fully populated limit struct ready for `RecurringAllowance` consumption.
    function _addTimeBoundsToDepositLimit(bytes32 policyId, DepositLimitConfig memory depositLimitConfig)
        internal
        view
        returns (RecurringAllowance.Limit memory depositLimit)
    {
        (uint48 start, uint48 end) = _getValidityWindowAsLimitBounds(policyId);
        return RecurringAllowance.Limit({
            allowance: depositLimitConfig.allowance, period: depositLimitConfig.period, start: start, end: end
        });
    }

    /// @dev Builds the low-level call components for a Morpho vault `deposit`, along with the ERC-20
    ///      approval that must precede it. The vault's `asset()` is queried on-chain to determine the
    ///      token to approve, and the vault itself is both the call target and the approval spender.
    ///
    /// @param lendPolicyConfig Policy config containing the pinned vault address.
    /// @param receiver         Address that will receive the minted vault shares (always the account).
    /// @param depositAssets    Amount of underlying assets to deposit.
    ///
    /// @return target          Call target (the vault).
    /// @return value           Native value to send (always 0).
    /// @return callData        ABI-encoded `IMorphoVault.deposit(depositAssets, receiver)` calldata.
    /// @return approvalToken   ERC-20 token to approve (the vault's underlying asset).
    /// @return approvalSpender Address to approve (the vault).
    function _buildVaultDepositCall(LendPolicyConfig memory lendPolicyConfig, address receiver, uint256 depositAssets)
        internal
        view
        returns (address target, uint256 value, bytes memory callData, address approvalToken, address approvalSpender)
    {
        target = lendPolicyConfig.vault;
        value = 0;

        approvalToken = IMorphoVault(lendPolicyConfig.vault).asset();
        approvalSpender = lendPolicyConfig.vault;
        callData = abi.encodeWithSelector(IMorphoVault.deposit.selector, depositAssets, receiver);
        return (target, value, callData, approvalToken, approvalSpender);
    }

    /// @dev Returns the EIP-712 domain name and version used for executor signature verification.
    ///
    /// @return name    Domain name (`"Morpho Lend Policy"`).
    /// @return version Domain version (`"1"`).
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Lend Policy";
        version = "1";
    }
}

