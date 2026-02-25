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
        /// @dev Maximum deposits per recurring period window, in the vault asset token's smallest unit (ERC20 decimals).
        uint160 allowance;
        /// @dev RecurringAllowance.Limit.period length in seconds.
        uint40 period;
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

    /// @notice Thrown when the vault address has no deployed code.
    error VaultNotContract(address vault);

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
        (, bytes memory policySpecificConfig) = _decodeAOAConfig(policyConfig);

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
    function _onAOAInstall(bytes32, address, AOAConfig memory, bytes memory policySpecificConfig) internal override {
        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        if (lendPolicyConfig.vault.code.length == 0) revert VaultNotContract(lendPolicyConfig.vault);
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Executes a Morpho vault deposit, enforcing recurring allowance bounds.
    function _onAOAExecute(
        bytes32 policyId,
        address account,
        AOAConfig memory,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        // Decode config and action data; validate deposit amount.
        LendPolicyConfig memory lendPolicyConfig = abi.decode(policySpecificConfig, (LendPolicyConfig));
        LendData memory lendData = abi.decode(actionData, (LendData));
        if (lendData.depositAssets == 0) revert ZeroAmount();

        // Consume recurring allowance for this period.
        RecurringAllowance.useLimit(
            _depositLimitState,
            policyId,
            _addTimeBoundsToDepositLimit(policyId, lendPolicyConfig.depositLimit),
            lendData.depositAssets
        );

        // Build wallet call plan: approve vault's underlying asset, then deposit into vault.
        address vault = lendPolicyConfig.vault;
        address asset = IMorphoVault(vault).asset();

        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0] = CoinbaseSmartWallet.Call({
            target: asset,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, vault, lendData.depositAssets)
        });
        calls[1] = CoinbaseSmartWallet.Call({
            target: vault,
            value: 0,
            data: abi.encodeWithSelector(IMorphoVault.deposit.selector, lendData.depositAssets, account)
        });
        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);

        // No post-call data.
        postCallData = "";
    }

    /// @dev Constructs a full `RecurringAllowance.Limit` by combining the caller-supplied
    ///      `DepositLimitConfig` (allowance, period) with the policy's on-chain validity window
    ///      (start, end) read from the PolicyManager. A zero `validUntil` (no expiry) is mapped
    ///      to `type(uint40).max`.
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
        (,,, uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.policies(address(this), policyId);
        uint40 start = validAfter;
        uint40 end = validUntil == 0 ? type(uint40).max : validUntil;
        return RecurringAllowance.Limit({
            allowance: depositLimitConfig.allowance, period: depositLimitConfig.period, start: start, end: end
        });
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

