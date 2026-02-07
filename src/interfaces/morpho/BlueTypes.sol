// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title BlueTypes
///
/// @notice Minimal type definitions used by Morpho Blue interfaces.
///
/// @dev These types mirror the Morpho Blue ABI and are used for calldata/return values.

/// @notice Morpho Blue market identifier.
type Id is bytes32;

/// @notice Morpho Blue market params (immutable identifiers for a market).
struct MarketParams {
    /// @dev ERC20 token being lent/borrowed.
    address loanToken;
    /// @dev ERC20 token posted as collateral.
    address collateralToken;
    /// @dev Oracle providing collateral price.
    address oracle;
    /// @dev Interest rate model contract.
    address irm;
    /// @dev Liquidation loan-to-value threshold.
    uint256 lltv;
}

/// @notice Morpho Blue position snapshot.
struct Position {
    /// @dev Shares representing supplied assets.
    uint256 supplyShares;
    /// @dev Shares representing borrowed assets.
    uint128 borrowShares;
    /// @dev Collateral amount (collateral token smallest units).
    uint128 collateral;
}

/// @notice Morpho Blue market snapshot.
struct Market {
    /// @dev Total supplied assets.
    uint128 totalSupplyAssets;
    /// @dev Total supply shares.
    uint128 totalSupplyShares;
    /// @dev Total borrowed assets.
    uint128 totalBorrowAssets;
    /// @dev Total borrow shares.
    uint128 totalBorrowShares;
    /// @dev Last update timestamp (protocol-defined units).
    uint128 lastUpdate;
    /// @dev Fee value (protocol-defined units).
    uint128 fee;
}

