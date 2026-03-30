// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {MarketParams} from "../interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../interfaces/morpho/IMorphoBlue.sol";
import {IWETH} from "../interfaces/IWETH.sol";

import {MorphoLoanProtectionPolicy} from "./MorphoLoanProtectionPolicy.sol";

/// @title MorphoWethLoanProtectionPolicy
///
/// @notice Single-executor authorized policy that can supply WETH collateral to Morpho Blue by wrapping native ETH
///         first, if an account's LTV exceeds a trigger threshold.
///
/// @dev Extends `MorphoLoanProtectionPolicy` with a mandatory `WETH.deposit{value}()` call prepended to the account's
///      call plan. This policy MUST only be installed against Morpho markets whose collateral token is the configured
///      WETH address — the install hook enforces this.
///
///      WETH flow (3 calls): WETH.deposit{value}() → WETH.approve(MORPHO) → Morpho.supplyCollateral
///
///      The account must hold sufficient native ETH (not WETH) for the top-up amount, since the policy wraps ETH
///      into WETH on behalf of the account during execution.
///
///      All other semantics (one-shot execution, trigger LTV, one active policy per (account, marketId)) are
///      inherited from `MorphoLoanProtectionPolicy`.
contract MorphoWethLoanProtectionPolicy is MorphoLoanProtectionPolicy {
    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice WETH contract address for this chain.
    address public immutable WETH;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when the WETH constructor argument has no deployed code.
    ///
    /// @param weth The address that was provided.
    error WethNotContract(address weth);

    /// @notice Thrown when the market's collateral token does not match the configured WETH address.
    ///
    /// @param collateralToken The market's collateral token.
    /// @param weth The configured WETH address.
    error CollateralNotWeth(address collateralToken, address weth);

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Constructs the WETH loan protection policy.
    ///
    /// @param policyManager Address of the `PolicyManager` authorized to call hooks.
    /// @param admin Address that receives `DEFAULT_ADMIN_ROLE` and `PAUSER_ROLE`.
    /// @param morpho_ Morpho Blue singleton contract address.
    /// @param weth_ WETH contract address for this chain (must be a deployed contract).
    constructor(address policyManager, address admin, address morpho_, address weth_)
        MorphoLoanProtectionPolicy(policyManager, admin, morpho_)
    {
        if (_isNotPersistentCode(weth_)) revert WethNotContract(weth_);
        WETH = weth_;
    }

    ////////////////////////////////////////////////////////////////
    ///                 External View Functions                  ///
    ////////////////////////////////////////////////////////////////

    /// @notice Convenience alias for `WETH` (lowercase getter).
    function weth() external view returns (address) {
        return WETH;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc MorphoLoanProtectionPolicy
    ///
    /// @dev Calls the parent install hook, then validates that the market's collateral token matches
    ///      the configured WETH address. Reverts with `CollateralNotWeth` if there is a mismatch.
    function _onSingleExecutorInstall(
        bytes32 policyId,
        address account,
        SingleExecutorConfig memory singleExecutorConfig,
        bytes memory policySpecificConfig
    ) internal override {
        super._onSingleExecutorInstall(policyId, account, singleExecutorConfig, policySpecificConfig);

        // Validate that this market actually uses WETH as collateral.
        LoanProtectionPolicyConfig memory config = abi.decode(policySpecificConfig, (LoanProtectionPolicyConfig));
        MarketParams memory marketParams = IMorphoBlue(MORPHO).idToMarketParams(config.marketId);
        if (marketParams.collateralToken != WETH) revert CollateralNotWeth(marketParams.collateralToken, WETH);
    }

    /// @inheritdoc MorphoLoanProtectionPolicy
    ///
    /// @dev Overrides the parent execute to build a 3-call plan that wraps native ETH into WETH before
    ///      approving and supplying collateral to Morpho.
    function _onSingleExecutorExecute(
        bytes32 policyId,
        address account,
        SingleExecutorConfig memory,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        // One-shot guard: revert if already used, otherwise mark consumed.
        if (_usedPolicyId[policyId]) revert PolicyAlreadyUsed(policyId);
        _usedPolicyId[policyId] = true;

        // Decode config and resolve on-chain market params (reverts if market is uninitialized).
        LoanProtectionPolicyConfig memory config = abi.decode(policySpecificConfig, (LoanProtectionPolicyConfig));
        MarketParams memory marketParams = _requireMarketParams(config.marketId);

        // Validate top-up amount and enforce LTV trigger.
        uint256 topUpAssets;
        {
            TopUpData memory topUp = abi.decode(actionData, (TopUpData));
            topUpAssets = topUp.topUpAssets;
            if (topUpAssets == 0) revert ZeroAmount();
            if (topUpAssets > config.maxTopUpAssets) revert TopUpAboveMax(topUpAssets, config.maxTopUpAssets);

            uint256 currentLtv = _computeCurrentLtv(config, marketParams, account);
            if (currentLtv < config.triggerLtv) revert HealthyPosition(currentLtv, config.triggerLtv);
        }

        // Build wallet call plan: wrap ETH → approve WETH → supply collateral to Morpho.
        // No zero-approve step needed: WETH is a standard ERC-20 (unlike USDT-style tokens in the parent).
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](3);
        calls[0] = CoinbaseSmartWallet.Call({
            target: WETH, value: topUpAssets, data: abi.encodeWithSelector(IWETH.deposit.selector)
        });
        calls[1] = CoinbaseSmartWallet.Call({
            target: WETH, value: 0, data: abi.encodeWithSelector(IERC20.approve.selector, MORPHO, topUpAssets)
        });
        calls[2] = CoinbaseSmartWallet.Call({
            target: MORPHO,
            value: 0,
            data: abi.encodeWithSelector(
                IMorphoBlue.supplyCollateral.selector, marketParams, topUpAssets, account, bytes("")
            )
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = "";
    }

    /// @dev Returns the EIP-712 domain name and version used for executor signature verification.
    ///
    /// @return name    Domain name (`"Morpho WETH Loan Protection Policy"`).
    /// @return version Domain version (`"1"`).
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho WETH Loan Protection Policy";
        version = "1";
    }
}
