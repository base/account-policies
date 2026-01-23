// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721} from "openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";
import {ERC165Checker} from "openzeppelin-contracts/contracts/utils/introspection/ERC165Checker.sol";
import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";
import {EIP712} from "solady/utils/EIP712.sol";

import {SpendHook} from "../SpendPermissionSpendHooks/SpendHook.sol";
import {Policy} from "./Policy.sol";

/// @notice Spend permissions policy.
contract SpendPolicy is EIP712, Policy {
    using SafeERC20 for IERC20;

    struct SpendPermission {
        address account;
        address spender;
        address token;
        uint160 allowance;
        uint48 period;
        uint48 start;
        uint48 end;
        uint256 salt;
        bytes extraData;
        address spendHook;
        bytes spendHookConfig;
    }

    struct PeriodSpend {
        uint48 start;
        uint48 end;
        uint160 spend;
    }

    bytes32 public constant SPEND_PERMISSION_TYPEHASH = keccak256(
        "SpendPermission(address account,address spender,address token,uint160 allowance,uint48 period,uint48 start,uint48 end,uint256 salt,bytes extraData,address spendHook,bytes spendHookConfig)"
    );

    mapping(bytes32 policyId => PeriodSpend) internal _lastUpdatedPeriod;
    mapping(bytes32 policyId => bytes32 configHash) internal _configHashes;

    event SpendPermissionUsed(
        bytes32 indexed policyId,
        address indexed account,
        address indexed spender,
        address token,
        PeriodSpend periodSpend
    );

    error ERC721TokenNotSupported(address token);
    error SpendPermissionNotCallableForNativeToken();
    error MissingSpendHookForNativeToken();
    error InvalidPolicyConfigAccount(address actual, address expected);
    error ZeroToken();
    error ZeroSpender();
    error ZeroAllowance();
    error ZeroPeriod();
    error InvalidStartEnd(uint48 start, uint48 end);
    error ZeroValue();
    error BeforeSpendPermissionStart(uint48 currentTimestamp, uint48 start);
    error AfterSpendPermissionEnd(uint48 currentTimestamp, uint48 end);
    error SpendValueOverflow(uint256 value);
    error ExceededSpendPermission(uint256 value, uint256 allowance);
    error NativeTokenTransferFailed(address to, uint256 value);
    error Unauthorized(address caller);
    error PolicyConfigHashMismatch(bytes32 actual, bytes32 expected);

    constructor(address policyManager) Policy(policyManager) {}

    receive() external payable {}

    function _onInstall(bytes32 policyId, address account, bytes calldata policyConfig, address caller) internal override {
        caller;
        _configHashes[policyId] = keccak256(policyConfig);
        SpendPermission memory sp = abi.decode(policyConfig, (SpendPermission));
        if (sp.account != account) revert InvalidPolicyConfigAccount(sp.account, account);
    }

    function _onRevoke(bytes32 policyId, address account, address caller) internal override {
        if (caller != account) revert InvalidSender(caller, account);
        delete _configHashes[policyId];
        delete _lastUpdatedPeriod[policyId];
    }

    /// @dev `policyConfig` is encoded SpendPermission. `policyData` encodes `(uint160 value, bytes prepData)`.
    function _onExecute(
        bytes32 policyId,
        address account,
        bytes calldata policyConfig,
        bytes calldata policyData,
        address caller
    ) internal override returns (bytes memory accountCallData, bytes memory postCallData) {
        bytes32 expected = _configHashes[policyId];
        bytes32 actual = keccak256(policyConfig);
        if (expected != actual) revert PolicyConfigHashMismatch(actual, expected);

        SpendPermission memory sp = abi.decode(policyConfig, (SpendPermission));
        if (sp.account != account) revert InvalidPolicyConfigAccount(sp.account, account);

        if (caller != sp.spender) revert Unauthorized(caller);

        (uint160 value, bytes memory prepData) = abi.decode(policyData, (uint160, bytes));
        _useSpendPermission(policyId, sp, value);

        // Token-specific behavior (approvals, balance abstraction, native ETH transfer, etc.) is handled by the spend
        // hook. For native token spends, we require a hook (e.g. NativeTokenSpendHook) since the policy cannot send ETH
        // itself.
        if (sp.spendHook == address(0) && sp.token == NATIVE_TOKEN) revert MissingSpendHookForNativeToken();

        if (sp.spendHook != address(0)) {
            CoinbaseSmartWallet.Call[] memory calls = SpendHook(sp.spendHook).prepare(sp, value, prepData);
            if (calls.length == 1) {
                accountCallData = abi.encodeWithSelector(
                    CoinbaseSmartWallet.execute.selector, calls[0].target, calls[0].value, calls[0].data
                );
            } else if (calls.length > 1) {
                accountCallData = abi.encodeWithSelector(CoinbaseSmartWallet.executeBatch.selector, calls);
            }
        }

        // Finalize in the policy post-call:
        // - ERC20: transferFrom(account -> recipient) using allowance granted during prep
        // - ETH: transfer(value) out of this policy (funded by NativeTokenSpendHook)
        postCallData = abi.encodeWithSelector(this.afterExecute.selector, sp.account, sp.token, sp.spender, value);
    }

    function afterExecute(address account, address token, address recipient, uint160 value)
        external
        onlyPolicyManager
    {
        if (token != NATIVE_TOKEN) {
            IERC20(token).safeTransferFrom(account, recipient, value);
        } else {
            // Spend hook must have transferred ETH from the account into this policy.
            (bool ok,) = recipient.call{value: value}("");
            if (!ok) revert NativeTokenTransferFailed(recipient, value);
        }
    }

    function getHash(SpendPermission memory sp) public view returns (bytes32) {
        return _hashTypedData(
            keccak256(
                abi.encode(
                    SPEND_PERMISSION_TYPEHASH,
                    sp.account,
                    sp.spender,
                    sp.token,
                    sp.allowance,
                    sp.period,
                    sp.start,
                    sp.end,
                    sp.salt,
                    keccak256(sp.extraData),
                    sp.spendHook,
                    keccak256(sp.spendHookConfig)
                )
            )
        );
    }

    function _getCurrentPeriod(bytes32 policyId, SpendPermission memory sp) internal view returns (PeriodSpend memory) {
        uint48 currentTimestamp = uint48(block.timestamp);
        if (currentTimestamp < sp.start) revert BeforeSpendPermissionStart(currentTimestamp, sp.start);
        if (currentTimestamp >= sp.end) revert AfterSpendPermissionEnd(currentTimestamp, sp.end);

        PeriodSpend memory lastUpdated = _lastUpdatedPeriod[policyId];
        bool lastExists = lastUpdated.spend != 0;
        bool lastStillActive = currentTimestamp < lastUpdated.end;
        if (lastExists && lastStillActive) return lastUpdated;

        uint48 currentPeriodProgress = (currentTimestamp - sp.start) % sp.period;
        uint48 start = currentTimestamp - currentPeriodProgress;
        bool endOverflow = uint256(start) + uint256(sp.period) > sp.end;
        uint48 end = endOverflow ? sp.end : start + sp.period;
        return PeriodSpend({start: start, end: end, spend: 0});
    }

    function _useSpendPermission(bytes32 policyId, SpendPermission memory sp, uint160 value) internal {
        if (value == 0) revert ZeroValue();
        if (sp.token == address(0)) revert ZeroToken();
        if (sp.token != NATIVE_TOKEN) {
            if (ERC165Checker.supportsInterface(sp.token, type(IERC721).interfaceId)) {
                revert ERC721TokenNotSupported(sp.token);
            }
        }
        if (sp.spender == address(0)) revert ZeroSpender();
        if (sp.period == 0) revert ZeroPeriod();
        if (sp.allowance == 0) revert ZeroAllowance();
        if (sp.start >= sp.end) revert InvalidStartEnd(sp.start, sp.end);

        PeriodSpend memory current = _getCurrentPeriod(policyId, sp);
        uint256 totalSpend = uint256(value) + uint256(current.spend);
        if (totalSpend > type(uint160).max) revert SpendValueOverflow(totalSpend);
        if (totalSpend > sp.allowance) revert ExceededSpendPermission(totalSpend, sp.allowance);

        // forge-lint: disable-next-line(unsafe-typecast)
        current.spend = uint160(totalSpend);
        _lastUpdatedPeriod[policyId] = current;
        emit SpendPermissionUsed(
            policyId,
            sp.account,
            sp.spender,
            sp.token,
            PeriodSpend({start: current.start, end: current.end, spend: value})
        );
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Spend Policy";
        version = "1";
    }
}

