// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Id, Market, MarketParams, Position} from "./BlueTypes.sol";

/// @dev Minimal Morpho Blue interface needed for collateral top-ups.
interface IMorphoBlue {
    function idToMarketParams(Id id) external view returns (MarketParams memory);
    function position(Id id, address user) external view returns (Position memory p);
    function market(Id id) external view returns (Market memory m);

    function supplyCollateral(MarketParams memory marketParams, uint256 assets, address onBehalf, bytes memory data)
        external;
}

