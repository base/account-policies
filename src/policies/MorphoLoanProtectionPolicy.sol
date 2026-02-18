// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Id, Market, MarketParams, Position} from "../interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../interfaces/morpho/IMorphoBlue.sol";
import {IOracle} from "../interfaces/morpho/IOracle.sol";

import {AOAPolicy} from "./AOAPolicy.sol";

/// @title MorphoLoanProtectionPolicy
///
/// @notice AOA policy that can supply collateral to Morpho Blue if an account's LTV exceeds a trigger threshold.
///
/// @dev Properties:
///      - pinned Morpho Blue contract + pinned `marketId` (market params are looked up onchain and required to exist)
///      - trigger LTV threshold
///      - one-shot execution (top-up amount chosen per execution, bounded by a max committed at install time)
///      - one active policy per (account, marketId)
contract MorphoLoanProtectionPolicy is AOAPolicy {
    ////////////////////////////////////////////////////////////////
    ///                         Types                            ///
    ////////////////////////////////////////////////////////////////

    /// @notice Policy-specific config for Morpho Blue loan protection.
    struct LoanProtectionPolicyConfig {
        /// @dev Morpho Blue contract address.
        /// @review is this some singleton or a specific vault? if singleton, then seems like we don't need one per config
        address morpho;
        /// @dev Morpho Blue market identifier.
        Id marketId;

        // LTV constraints in WAD (1e18 = 100%).
        /// @dev Position must be at or above this LTV (wad) to trigger protection.
        uint256 triggerLtv;
        /// @dev Maximum collateral top-up amount allowed per execution (collateral token smallest units).
        uint256 maxTopUpAssets;
    }

    /// @notice Policy-specific execution payload for collateral top-ups.
    struct TopUpData {
        /// @dev Collateral top-up amount (collateral token smallest units).
        /// @review usually opt to have some "amount" or "value" in the name if the field is a number
        uint256 topUpAssets;
    }

    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Tracks one active policy per (account, marketId).
    mapping(address account => mapping(bytes32 marketKey => bytes32 policyId)) internal _activePolicyByMarket;

    /// @notice Stored market key per policy instance to validate uninstallation.
    mapping(bytes32 policyId => bytes32 marketKey) internal _marketKeyByPolicyId;

    /// @notice Tracks whether a policy instance has been executed already (one-shot).
    /// @review would appreciate @dev comment on why this is needed for my initial orientation
    mapping(bytes32 policyId => bool used) internal _usedPolicyId;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when the Morpho market params for the pinned `marketId` are not found/initialized.
    error MarketNotFound(Id marketId);

    /// @notice Thrown when the Morpho Blue address is zero.
    error ZeroMorpho();

    /// @notice Thrown when the marketId is zero.
    error ZeroMarketId();

    /// @notice Thrown when attempting a zero-amount top-up.
    error ZeroAmount();

    /// @notice Thrown when the requested top-up amount exceeds the config max.
    error TopUpAboveMax(uint256 topUpAssets, uint256 maxTopUpAssets);

    /// @notice Thrown when the position is below the trigger LTV (i.e., is considered healthy).
    error HealthyPosition(uint256 currentLtv, uint256 triggerLtv);

    /// @notice Thrown when the policyId has already been used (one-shot).
    error PolicyAlreadyUsed(bytes32 policyId);

    /// @notice Thrown when the oracle price results in a zero collateral value.
    error ZeroCollateralValue();

    /// @notice Thrown when an account attempts to install multiple active policies for the same marketId.
    error PolicyAlreadyInstalledForMarket(address account, Id marketId);

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

    /// @notice Return whether the policyId has been used (one-shot).
    ///
    /// @param policyId Policy identifier to check.
    ///
    /// @return True if the policy has already executed its one-shot top-up.
    /// @review Can save us a function if just make the storage public
    function isPolicyUsed(bytes32 policyId) external view returns (bool) {
        return _usedPolicyId[policyId];
    }

    ////////////////////////////////////////////////////////////////
    ///                    Internal Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Validates config, enforces one-policy-per-market, and stores market linkage for uninstall.
    function _onAOAInstall(bytes32 policyId, AOAConfig memory aoaConfig, bytes memory policySpecificConfig)
        internal
        override
    {
        LoanProtectionPolicyConfig memory config = abi.decode(policySpecificConfig, (LoanProtectionPolicyConfig));
        if (config.morpho == address(0)) revert ZeroMorpho();
        if (Id.unwrap(config.marketId) == bytes32(0)) revert ZeroMarketId();
        if (config.maxTopUpAssets == 0) revert ZeroAmount();

        // Ensure the pinned market exists on this Morpho instance.
        _requireMarketParams(config.morpho, config.marketId);

        // Ensure only one active policy per (account, market).
        bytes32 marketKey = Id.unwrap(config.marketId);
        if (_activePolicyByMarket[aoaConfig.account][marketKey] != bytes32(0)) {
            revert PolicyAlreadyInstalledForMarket(aoaConfig.account, config.marketId);
        }
        _activePolicyByMarket[aoaConfig.account][marketKey] = policyId;
        _marketKeyByPolicyId[policyId] = marketKey;
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Clears per-install state for a policy instance.
    function _onAOAUninstall(bytes32 policyId, address account, address) internal override {
        _clearInstallState(policyId, account);
    }

    /// @dev Clears per-install state mappings (`_activePolicyByMarket`, `_marketKeyByPolicyId`) if they
    ///      still reference `policyId`. Safe to call even if state was already cleared or never set.
    ///
    /// @param policyId Policy identifier whose state should be cleared.
    /// @param account  Account associated with the policy instance.
    function _clearInstallState(bytes32 policyId, address account) internal {
        bytes32 marketKey = _marketKeyByPolicyId[policyId];
        if (marketKey != bytes32(0) && _activePolicyByMarket[account][marketKey] == policyId) {
            delete _activePolicyByMarket[account][marketKey];
        }
        delete _marketKeyByPolicyId[policyId];
    }

    /// @inheritdoc AOAPolicy
    ///
    /// @dev Executes a collateral top-up once, enforcing trigger LTV and one-shot semantics.
    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoaConfig,
        bytes memory policySpecificConfig,
        bytes memory actionData
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        if (_usedPolicyId[policyId]) revert PolicyAlreadyUsed(policyId);
        /// @review put in else block? Not sure if using gas unnecessarily if we usually try to set to an already set value?
        _usedPolicyId[policyId] = true;

        /// @review give more comments to skim pls
        LoanProtectionPolicyConfig memory config = abi.decode(policySpecificConfig, (LoanProtectionPolicyConfig));
        /// @review Are there any cases where something would change between install and execute that requires re-running these checks?
        MarketParams memory marketParams = _requireMarketParams(config.morpho, config.marketId);
        TopUpData memory topUp = abi.decode(actionData, (TopUpData));
        uint256 topUpAssets = topUp.topUpAssets;
        if (topUpAssets == 0) revert ZeroAmount();
        if (topUpAssets > config.maxTopUpAssets) revert TopUpAboveMax(topUpAssets, config.maxTopUpAssets);
        _enforceTriggerLtv(config, marketParams, aoaConfig.account);

        // Build wallet call plan:
        // - approve(collateralToken, morpho, amount)
        // - morpho.supplyCollateral(marketParams, amount, account, "")
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0] = CoinbaseSmartWallet.Call({
            target: marketParams.collateralToken,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, config.morpho, topUpAssets)
        });
        calls[1] = CoinbaseSmartWallet.Call({
            target: config.morpho,
            value: 0,
            data: abi.encodeWithSelector(
                IMorphoBlue.supplyCollateral.selector, marketParams, topUpAssets, aoaConfig.account, bytes("")
            )
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = "";
    }

    /// @dev Computes the account's current LTV for the configured market and reverts with `HealthyPosition`
    ///      if it is strictly below the `triggerLtv` threshold (i.e., the position does not need protection).
    ///
    /// @param config       Policy config containing the trigger LTV and Morpho address.
    /// @param marketParams On-chain market parameters for the pinned market.
    /// @param account      Account whose position LTV is evaluated.
    /// @review feels like we don't need this if we just inline it's only usage. I'm happy with _computeCurrentLtv as separate function because it's doing a lot more lifting
    function _enforceTriggerLtv(
        LoanProtectionPolicyConfig memory config,
        MarketParams memory marketParams,
        address account
    ) internal view {
        uint256 currentLtv = _computeCurrentLtv(config, marketParams, account);
        if (currentLtv < config.triggerLtv) revert HealthyPosition(currentLtv, config.triggerLtv);
    }

    /// @notice Looks up market params from `marketId` and reverts if the market is not initialized.
    ///
    /// @param morphoAddress Morpho Blue contract address.
    /// @param marketId Market identifier.
    ///
    /// @return marketParams Market parameters for the given marketId.
    function _requireMarketParams(address morphoAddress, Id marketId)
        internal
        view
        returns (MarketParams memory marketParams)
    {
        marketParams = IMorphoBlue(morphoAddress).idToMarketParams(marketId);
        // Treat zeroed params as "market does not exist / not initialized on this Morpho instance".
        if (
            marketParams.loanToken == address(0) || marketParams.collateralToken == address(0)
                || marketParams.oracle == address(0) || marketParams.irm == address(0) || marketParams.lltv == 0
        ) revert MarketNotFound(marketId);
    }

    /// @dev Computes the account's current LTV as a WAD-scaled value (1e18 = 100%) using the Morpho Blue
    ///      position, market totals, and oracle price. Reverts with `ZeroCollateralValue` if the collateral
    ///      position has zero value after oracle pricing (which would cause a division-by-zero in the LTV
    ///      calculation).
    ///
    /// @param config       Policy config containing the Morpho address and market identifier.
    /// @param marketParams On-chain market parameters (used to locate the oracle and collateral token).
    /// @param account      Account whose position is evaluated.
    ///
    /// @return currentLtvWad Current LTV in WAD (1e18 = 100%).
    function _computeCurrentLtv(
        LoanProtectionPolicyConfig memory config,
        MarketParams memory marketParams,
        address account
    ) internal view returns (uint256 currentLtvWad) {
        IMorphoBlue morphoBlue = IMorphoBlue(config.morpho);
        Position memory position = morphoBlue.position(config.marketId, account);
        Market memory market = morphoBlue.market(config.marketId);

        uint256 collateralBefore = uint256(position.collateral);

        // Debt assets derived from borrow shares and market totals.
        uint256 debtAssets;
        uint256 totalBorrowShares = uint256(market.totalBorrowShares);
        if (totalBorrowShares == 0) {
            debtAssets = 0;
        } else {
            debtAssets =
                Math.mulDiv(uint256(position.borrowShares), uint256(market.totalBorrowAssets), totalBorrowShares);
        }

        uint256 price = IOracle(marketParams.oracle).price(); // 1e36 scaled

        uint256 collateralValueBefore = Math.mulDiv(collateralBefore, price, 1e36);
        if (collateralValueBefore == 0) revert ZeroCollateralValue();

        currentLtvWad = Math.mulDiv(debtAssets, 1e18, collateralValueBefore);
    }

    /// @dev Returns the EIP-712 domain name and version used for executor signature verification.
    ///
    /// @return name    Domain name (`"Morpho Loan Protection Policy"`).
    /// @return version Domain version (`"1"`).
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Loan Protection Policy";
        version = "1";
    }
}

