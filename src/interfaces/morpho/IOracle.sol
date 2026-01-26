// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @dev Oracle interface required by Morpho Blue markets.
interface IOracle {
    /// @notice Returns the price of 1 collateral token quoted in 1 loan token, scaled by 1e36.
    function price() external view returns (uint256);
}

