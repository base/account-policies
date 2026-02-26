// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Id, Market, MarketParams, Position} from "./BlueTypes.sol";

/// @title IMorphoBlue
///
/// @notice Minimal Morpho Blue interface needed by policies in this repo.
interface IMorphoBlue {
    /// @notice Returns market params for a given market id.
    function idToMarketParams(Id id) external view returns (MarketParams memory);

    /// @notice Returns a position snapshot for a user in a market.
    function position(Id id, address user) external view returns (Position memory p);

    /// @notice Returns a market snapshot for a market id.
    function market(Id id) external view returns (Market memory m);

    /// @notice Supplies collateral for a position.
    function supplyCollateral(MarketParams memory marketParams, uint256 assets, address onBehalf, bytes memory data)
        external;

    /// @notice Accrues interest for the given market `marketParams`.
    function accrueInterest(MarketParams memory marketParams) external;
}

