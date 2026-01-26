// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @dev Morpho Blue market identifier.
type Id is bytes32;

/// @dev Morpho Blue market params (immutable identifiers for a market).
struct MarketParams {
    address loanToken;
    address collateralToken;
    address oracle;
    address irm;
    uint256 lltv;
}

/// @dev Morpho Blue position snapshot.
struct Position {
    uint256 supplyShares;
    uint128 borrowShares;
    uint128 collateral;
}

/// @dev Morpho Blue market snapshot.
struct Market {
    uint128 totalSupplyAssets;
    uint128 totalSupplyShares;
    uint128 totalBorrowAssets;
    uint128 totalBorrowShares;
    uint128 lastUpdate;
    uint128 fee;
}

