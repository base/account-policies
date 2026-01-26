// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Math} from "openzeppelin-contracts/contracts/utils/math/Math.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {Id, Market, MarketParams, Position} from "../interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../interfaces/morpho/IMorphoBlue.sol";
import {IOracle} from "../interfaces/morpho/IOracle.sol";

import {Policy} from "./Policy.sol";
import {RecurringAllowance} from "./accounting/RecurringAllowance.sol";

/// @notice Morpho Blue liquidation-protection policy: supplies collateral when LTV is high.
/// @dev Hard-enforces:
/// - pinned Morpho contract + pinned market params
/// - executor-signed execution intents (EIP-712)
/// - trigger LTV threshold
/// - post-protection LTV bounds (min + max)
/// - recurring allowance budget (in collateral-token units)
/// - one active policy per (account, marketId)
contract MorphoLoanProtectionPolicy is EIP712, Policy {
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);
    error MarketParamsMismatch();
    error ZeroExecutor();
    error ZeroMorpho();
    error ZeroMarketId();
    error ZeroAmount();
    error ZeroNonce();
    error SignatureExpired(uint256 currentTimestamp, uint256 deadline);
    error Unauthorized(address caller);
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

    /// @dev Active config hash per policy instance.
    mapping(bytes32 policyId => bytes32 configHash) internal _configHashByPolicyId;

    /// @dev One active policy per (account, marketId).
    mapping(address account => mapping(bytes32 marketId => bytes32 policyId)) internal _activePolicyByMarket;

    /// @dev Stored market key per policy instance to support clean revocation.
    mapping(bytes32 policyId => bytes32 marketId) internal _marketIdByPolicyId;

    /// @dev Recurring allowance state (budget in collateral units).
    RecurringAllowance.State internal _collateralLimitState;

    /// @dev Replay protection for executor intents.
    mapping(bytes32 policyId => mapping(uint256 nonce => bool used)) internal _usedNonces;

    struct Config {
        address executor;
        address morpho;
        Id marketId;
        MarketParams marketParams;

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

    struct PolicyData {
        TopUpData data;
        bytes signature; // executor signature
    }

    constructor(address policyManager) Policy(policyManager) {}

    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller)
        internal
        override
    {
        caller;
        Config memory cfg = abi.decode(policyConfig, (Config));
        if (cfg.executor == address(0)) revert ZeroExecutor();
        if (cfg.morpho == address(0)) revert ZeroMorpho();
        if (Id.unwrap(cfg.marketId) == bytes32(0)) revert ZeroMarketId();

        // Ensure market pinning is correct at install time.
        MarketParams memory marketParams = IMorphoBlue(cfg.morpho).idToMarketParams(cfg.marketId);
        if (
            marketParams.loanToken != cfg.marketParams.loanToken
                || marketParams.collateralToken != cfg.marketParams.collateralToken
                || marketParams.oracle != cfg.marketParams.oracle || marketParams.irm != cfg.marketParams.irm
                || marketParams.lltv != cfg.marketParams.lltv
        ) revert MarketParamsMismatch();

        // Ensure only one active policy per (account, market).
        bytes32 marketKey = Id.unwrap(cfg.marketId);
        if (_activePolicyByMarket[account][marketKey] != bytes32(0)) {
            revert PolicyAlreadyInstalledForMarket(account, cfg.marketId);
        }
        _activePolicyByMarket[account][marketKey] = policyId;
        _marketIdByPolicyId[policyId] = marketKey;

        _configHashByPolicyId[policyId] = keccak256(policyConfig);
    }

    function _onRevoke(bytes32 policyId, address account, address caller) internal override {
        if (caller != account) revert Unauthorized(caller);

        bytes32 marketKey = _marketIdByPolicyId[policyId];
        if (marketKey != bytes32(0) && _activePolicyByMarket[account][marketKey] == policyId) {
            delete _activePolicyByMarket[account][marketKey];
        }
        delete _marketIdByPolicyId[policyId];
        delete _configHashByPolicyId[policyId];
    }

    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        bytes32 expectedConfigHash = _configHashByPolicyId[policyId];
        bytes32 actualConfigHash = keccak256(policyConfig);
        if (expectedConfigHash != actualConfigHash) revert PolicyConfigHashMismatch(actualConfigHash, expectedConfigHash);

        Config memory cfg = abi.decode(policyConfig, (Config));
        PolicyData memory pd = abi.decode(policyData, (PolicyData));

        _validatePolicyData(policyId, account, expectedConfigHash, cfg, pd, caller);
        _enforceLtvBounds(cfg, account, pd.data.topUpAssets);

        // Enforce recurring budget in collateral-token units.
        RecurringAllowance.useLimit(_collateralLimitState, policyId, cfg.collateralLimit, pd.data.topUpAssets);

        // Build wallet call plan:
        // - approve(collateralToken, morpho, amount)
        // - morpho.supplyCollateral(marketParams, amount, account, callbackData)
        //
        // Note: We intentionally do NOT reset approval to 0; when approving exactly `amount`, a compliant ERC-20
        // will have its allowance fully consumed by Morpho's `transferFrom`.
        CoinbaseSmartWallet.Call[] memory calls = new CoinbaseSmartWallet.Call[](2);
        calls[0] = CoinbaseSmartWallet.Call({
            target: cfg.marketParams.collateralToken,
            value: 0,
            data: abi.encodeWithSelector(IERC20.approve.selector, cfg.morpho, pd.data.topUpAssets)
        });
        calls[1] = CoinbaseSmartWallet.Call({
            target: cfg.morpho,
            value: 0,
            data: abi.encodeWithSelector(
                IMorphoBlue.supplyCollateral.selector, cfg.marketParams, pd.data.topUpAssets, account, pd.data.callbackData
            )
        });

        accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
        postCallData = "";
    }

    function _validatePolicyData(
        bytes32 policyId,
        address account,
        bytes32 expectedConfigHash,
        Config memory cfg,
        PolicyData memory pd,
        address caller
    ) internal {
        if (pd.data.topUpAssets == 0) revert ZeroAmount();
        if (pd.data.nonce == 0) revert ZeroNonce();
        if (pd.data.deadline != 0 && block.timestamp > pd.data.deadline) {
            revert SignatureExpired(block.timestamp, pd.data.deadline);
        }
        if (_usedNonces[policyId][pd.data.nonce]) revert ExecutionNonceAlreadyUsed(policyId, pd.data.nonce);

        bytes32 callbackHash = keccak256(pd.data.callbackData);
        bytes32 topUpDataHash = keccak256(
            abi.encode(TOP_UP_DATA_TYPEHASH, pd.data.topUpAssets, pd.data.nonce, pd.data.deadline, callbackHash)
        );

        bytes32 digest = _getExecutionDigest(policyId, account, expectedConfigHash, topUpDataHash);
        bool ok = POLICY_MANAGER.PUBLIC_ERC6492_VALIDATOR()
            .isValidSignatureNowAllowSideEffects(cfg.executor, digest, pd.signature);
        if (!ok) revert Unauthorized(caller);

        _usedNonces[policyId][pd.data.nonce] = true;
    }

    function _enforceLtvBounds(Config memory cfg, address account, uint256 topUpAssets) internal view {
        (uint256 currentLtv, uint256 projectedLtv) = _computeLtvPair(cfg, account, topUpAssets);
        if (currentLtv < cfg.triggerLtv) revert HealthyPosition(currentLtv, cfg.triggerLtv);
        if (projectedLtv > cfg.maxPostProtectionLtv) revert ProjectedLtvTooHigh(projectedLtv, cfg.maxPostProtectionLtv);
        if (projectedLtv < cfg.minPostProtectionLtv) revert ProjectedLtvTooLow(projectedLtv, cfg.minPostProtectionLtv);
    }

    function _getExecutionDigest(bytes32 policyId, address account, bytes32 configHash, bytes32 policyDataHash)
        internal
        view
        returns (bytes32)
    {
        return _hashTypedData(keccak256(abi.encode(EXECUTION_TYPEHASH, policyId, account, configHash, policyDataHash)));
    }

    function _computeLtvPair(Config memory cfg, address account, uint256 topUpAssets)
        internal
        view
        returns (uint256 currentLtvWad, uint256 projectedLtvWad)
    {
        IMorphoBlue morpho = IMorphoBlue(cfg.morpho);
        Position memory p = morpho.position(cfg.marketId, account);
        Market memory m = morpho.market(cfg.marketId);

        uint256 collateralBefore = uint256(p.collateral);
        uint256 collateralAfter = collateralBefore + topUpAssets;

        // Debt assets derived from borrow shares and market totals.
        uint256 debtAssets;
        uint256 totalBorrowShares = uint256(m.totalBorrowShares);
        if (totalBorrowShares == 0) {
            debtAssets = 0;
        } else {
            debtAssets = Math.mulDiv(uint256(p.borrowShares), uint256(m.totalBorrowAssets), totalBorrowShares);
        }

        uint256 price = IOracle(cfg.marketParams.oracle).price(); // 1e36 scaled

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

