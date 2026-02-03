// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

import {Id, Market, MarketParams, Position} from "../interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../interfaces/morpho/IMorphoBlue.sol";
import {IOracle} from "../interfaces/morpho/IOracle.sol";

import {AOAPolicy} from "./AOAPolicy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @notice Morpho Blue liquidation-protection policy: supplies collateral when LTV is high.
/// @dev Hard-enforces:
/// - pinned Morpho contract + pinned market params
/// - executor-signed execution intents (EIP-712)
/// - trigger LTV threshold
/// - post-protection LTV bounds (min + max)
/// - recurring allowance budget (in collateral-token units)
/// - one active policy per (account, marketId)
contract MorphoLoanProtectionPolicy is AOAPolicy {
    error MarketNotFound(Id marketId);
    error ZeroMorpho();
    error ZeroMarketId();
    error ZeroAmount();
    error ZeroNonce();
    error SignatureExpired(uint256 currentTimestamp, uint256 deadline);
    error ExecutionNonceAlreadyUsed(bytes32 policyId, uint256 nonce);
    error HealthyPosition(uint256 currentLtv, uint256 triggerLtv);
    error ProjectedLtvTooHigh(uint256 projectedLtv, uint256 maxPostLtv);
    error ProjectedLtvTooLow(uint256 projectedLtv, uint256 minPostLtv);
    error ZeroCollateralValue();
    error PolicyAlreadyInstalledForMarket(address account, Id marketId);

    /// @dev Outer signed struct tying an execution to a policy instance.
    bytes32 public constant EXECUTION_TYPEHASH =
        keccak256("Execution(bytes32 policyId,address account,bytes32 policyConfigHash,bytes32 policyDataHash)");

    /// @dev Inner signed struct: what the executor is authorizing for a specific execution.
    bytes32 public constant TOP_UP_DATA_TYPEHASH =
        keccak256("TopUpData(uint256 topUpAssets,uint256 nonce,uint256 deadline,bytes32 callbackDataHash)");

    /// @dev One active policy per (account, marketId).
    mapping(address account => mapping(bytes32 marketId => bytes32 policyId)) internal _activePolicyByMarket;

    /// @dev Stored market key per policy instance to support clean uninstallation.
    mapping(bytes32 policyId => bytes32 marketId) internal _marketIdByPolicyId;

    /// @dev Recurring allowance state (budget in collateral units).
    RecurringAllowance.State internal _collateralLimitState;

    /// @dev Replay protection for executor intents.
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    struct MorphoConfig {
        address morpho;
        Id marketId;

        // LTV constraints in WAD (1e18 = 100%).
        uint256 triggerLtv;
        uint256 minPostProtectionLtv;
        uint256 maxPostProtectionLtv;

        // Budget in collateral-token units (smallest unit).
        RecurringAllowance.Limit collateralLimit;
    }

    struct TopUpData {
        uint256 topUpAssets; // collateral-token smallest units
        uint256 nonce; // replay protection
        uint256 deadline; // signature expiry (unix timestamp)
        bytes callbackData; // forwarded to Morpho's callback (optional)
    }

    constructor(address policyManager, address admin) AOAPolicy(policyManager, admin) {}

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

    function _getInstallWindowAsLimitBounds(bytes32 policyId) internal view returns (uint48 start, uint48 end) {
        (,,, uint40 validAfter, uint40 validUntil) = POLICY_MANAGER.getPolicyRecord(address(this), policyId);
        start = uint48(validAfter);
        end = validUntil == 0 ? type(uint48).max : uint48(validUntil);
    }

    function _applyInstallWindowBoundsIfUnset(bytes32 policyId, RecurringAllowance.Limit memory limit)
        internal
        view
        returns (RecurringAllowance.Limit memory)
    {
        // Sentinel: if config leaves both timestamps zero, bind allowance to the policy install window.
        if (limit.start == 0 && limit.end == 0) {
            (limit.start, limit.end) = _getInstallWindowAsLimitBounds(policyId);
        }
        return limit;
    }

    /// @notice Return recurring collateral limit usage for a policy instance.
    /// @dev Requires the config preimage so the contract can decode `collateralLimit` without storing it.
    function getCollateralLimitPeriodUsage(bytes32 policyId, bytes calldata policyConfig)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory lastUpdated, RecurringAllowance.PeriodUsage memory current)
    {
        _requireConfigHash(policyId, policyConfig);
        address account = POLICY_MANAGER.getAccountForPolicy(address(this), policyId);
        (AOAConfig memory aoa, bytes memory policySpecificConfig) = _decodeAOAConfig(account, policyConfig);
        aoa; // silence unused warning

        MorphoConfig memory config = abi.decode(policySpecificConfig, (MorphoConfig));
        config.collateralLimit = _applyInstallWindowBoundsIfUnset(policyId, config.collateralLimit);
        lastUpdated = RecurringAllowance.getLastUpdated(_collateralLimitState, policyId);
        current = RecurringAllowance.getCurrentPeriod(_collateralLimitState, policyId, config.collateralLimit);
    }

    /// @notice Return the last stored recurring collateral usage for a policy instance.
    function getCollateralLimitLastUpdated(bytes32 policyId)
        external
        view
        returns (RecurringAllowance.PeriodUsage memory)
    {
        return RecurringAllowance.getLastUpdated(_collateralLimitState, policyId);
    }

    function _onAOAInstall(bytes32 policyId, AOAConfig memory aoa, bytes memory policySpecificConfig)
        internal
        override
    {
        MorphoConfig memory config = abi.decode(policySpecificConfig, (MorphoConfig));
        if (config.morpho == address(0)) revert ZeroMorpho();
        if (Id.unwrap(config.marketId) == bytes32(0)) revert ZeroMarketId();

        // Ensure the pinned market exists on this Morpho instance.
        _requireMarketParams(config.morpho, config.marketId);

        // Ensure only one active policy per (account, market).
        bytes32 marketKey = Id.unwrap(config.marketId);
        if (_activePolicyByMarket[aoa.account][marketKey] != bytes32(0)) {
            revert PolicyAlreadyInstalledForMarket(aoa.account, config.marketId);
        }
        _activePolicyByMarket[aoa.account][marketKey] = policyId;
        _marketIdByPolicyId[policyId] = marketKey;
    }

    function _onAOAUninstall(bytes32 policyId, address account, address) internal override {
        _clearInstallState(policyId, account);
    }

    function _clearInstallState(bytes32 policyId, address account) internal {
        bytes32 marketKey = _marketIdByPolicyId[policyId];
        if (marketKey != bytes32(0) && _activePolicyByMarket[account][marketKey] == policyId) {
            delete _activePolicyByMarket[account][marketKey];
        }
        delete _marketIdByPolicyId[policyId];
    }

    function _onAOAExecute(
        bytes32 policyId,
        AOAConfig memory aoa,
        bytes memory policySpecificConfig,
        bytes memory actionData,
        bytes memory signature,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        MorphoConfig memory config = abi.decode(policySpecificConfig, (MorphoConfig));
        MarketParams memory marketParams = _requireMarketParams(config.morpho, config.marketId);
        TopUpData memory topUpData = abi.decode(actionData, (TopUpData));

        bytes32 expectedConfigHash = _configHashByPolicyId[policyId];
        _validatePolicyData(policyId, aoa.account, expectedConfigHash, aoa.executor, topUpData, signature, caller);
        _enforceLtvBounds(config, marketParams, aoa.account, topUpData.topUpAssets);

        // Enforce recurring budget in collateral-token units.
        RecurringAllowance.Limit memory collateralLimit =
            _applyInstallWindowBoundsIfUnset(policyId, config.collateralLimit);
        RecurringAllowance.useLimit(_collateralLimitState, policyId, collateralLimit, topUpData.topUpAssets);

        // Build wallet call plan:
        // - approve(collateralToken, morpho, amount)
        // - morpho.supplyCollateral(marketParams, amount, account, callbackData)
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0] = CoinbaseSmartWallet.Call({
            target: marketParams.collateralToken,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, config.morpho, topUpData.topUpAssets)
        });
        calls[1] = CoinbaseSmartWallet.Call({
            target: config.morpho,
            value: 0,
            data: abi.encodeWithSelector(
                IMorphoBlue.supplyCollateral.selector,
                marketParams,
                topUpData.topUpAssets,
                aoa.account,
                topUpData.callbackData
            )
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = "";
    }

    function _validatePolicyData(
        bytes32 policyId,
        address account,
        bytes32 expectedConfigHash,
        address executor,
        TopUpData memory topUpData,
        bytes memory signature,
        address caller
    ) internal {
        if (topUpData.topUpAssets == 0) revert ZeroAmount();
        if (topUpData.nonce == 0) revert ZeroNonce();
        if (topUpData.deadline != 0 && block.timestamp > topUpData.deadline) {
            revert SignatureExpired(block.timestamp, topUpData.deadline);
        }
        if (_usedNonces[policyId][topUpData.nonce]) revert ExecutionNonceAlreadyUsed(policyId, topUpData.nonce);

        bytes32 callbackHash = keccak256(topUpData.callbackData);
        bytes32 topUpDataHash =
            keccak256(
                abi.encode(TOP_UP_DATA_TYPEHASH, topUpData.topUpAssets, topUpData.nonce, topUpData.deadline, callbackHash)
            );

        bytes32 digest = _getExecutionDigest(policyId, account, expectedConfigHash, topUpDataHash);
        bool ok = _isValidExecutorSig(executor, digest, signature);
        if (!ok) revert Unauthorized(caller);

        _usedNonces[policyId][topUpData.nonce] = true;
    }

    function _enforceLtvBounds(
        MorphoConfig memory config,
        MarketParams memory marketParams,
        address account,
        uint256 topUpAssets
    ) internal view {
        (uint256 currentLtv, uint256 projectedLtv) = _computeLtvPair(config, marketParams, account, topUpAssets);
        if (currentLtv < config.triggerLtv) revert HealthyPosition(currentLtv, config.triggerLtv);
        if (projectedLtv > config.maxPostProtectionLtv) {
            revert ProjectedLtvTooHigh(projectedLtv, config.maxPostProtectionLtv);
        }
        if (projectedLtv < config.minPostProtectionLtv) {
            revert ProjectedLtvTooLow(projectedLtv, config.minPostProtectionLtv);
        }
    }

    function _getExecutionDigest(bytes32 policyId, address account, bytes32 configHash, bytes32 policyDataHash)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedData(keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, account, configHash, policyDataHash)));
    }

    function _computeLtvPair(
        MorphoConfig memory config,
        MarketParams memory marketParams,
        address account,
        uint256 topUpAssets
    ) internal view returns (uint256 currentLtvWad, uint256 projectedLtvWad) {
        IMorphoBlue morphoBlue = IMorphoBlue(config.morpho);
        Position memory position = morphoBlue.position(config.marketId, account);
        Market memory market = morphoBlue.market(config.marketId);

        uint256 collateralBefore = uint256(position.collateral);
        uint256 collateralAfter = collateralBefore + topUpAssets;

        // Debt assets derived from borrow shares and market totals.
        uint256 debtAssets;
        uint256 totalBorrowShares = uint256(market.totalBorrowShares);
        if (totalBorrowShares == 0) {
            debtAssets = 0;
        } else {
            debtAssets = Math.mulDiv(uint256(position.borrowShares), uint256(market.totalBorrowAssets), totalBorrowShares);
        }

        uint256 price = IOracle(marketParams.oracle).price(); // 1e36 scaled

        uint256 collateralValueBefore = Math.mulDiv(collateralBefore, price, 1e36);
        uint256 collateralValueAfter = Math.mulDiv(collateralAfter, price, 1e36);
        if (collateralValueBefore == 0 || collateralValueAfter == 0) revert ZeroCollateralValue();

        currentLtvWad = Math.mulDiv(debtAssets, 1e18, collateralValueBefore);
        projectedLtvWad = Math.mulDiv(debtAssets, 1e18, collateralValueAfter);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Morpho Loan Protection Policy";
        version = "1";
    }
}

