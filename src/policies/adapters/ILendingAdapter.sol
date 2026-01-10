// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Protocol adapter for LendingPolicy.
/// @dev Adapters should be pure/view w.r.t. call construction and risk checks.
interface ILendingAdapter {
    enum Action {
        Supply,
        Withdraw,
        Borrow,
        Repay
    }

    /// @notice Build the protocol call the wallet should execute for a lending action.
    /// @param account The wallet/account executing the call.
    /// @param action The lending action.
    /// @param asset The asset being supplied/withdrawn/borrowed/repaid.
    /// @param amount The amount for the action (protocol units).
    /// @param adapterConfig Adapter-specific configuration (e.g., pool/market addresses, rate mode, referral code).
    /// @param actionData Adapter-specific action data (e.g., permit payloads, extra params).
    /// @return target The address the wallet should call.
    /// @return value The native value to send with the call (usually 0).
    /// @return data ABI-encoded calldata for the protocol call.
    /// @return approvalToken If non-zero, the token that must be approved by the wallet.
    /// @return approvalSpender If non-zero, the spender that should be approved by the wallet.
    function buildCall(
        address account,
        Action action,
        address asset,
        uint256 amount,
        bytes calldata adapterConfig,
        bytes calldata actionData
    )
        external
        view
        returns (address target, uint256 value, bytes memory data, address approvalToken, address approvalSpender);

    /// @notice Return a risk metric for the account (normalized however the adapter chooses).
    /// @dev For Aave-like systems, this should return health factor in 1e18 fixed-point.
    function healthFactor(address account, bytes calldata adapterConfig) external view returns (uint256);
}

