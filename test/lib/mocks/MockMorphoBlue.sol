// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {Id, Market, MarketParams, Position} from "../../../src/interfaces/morpho/BlueTypes.sol";
import {IMorphoBlue} from "../../../src/interfaces/morpho/IMorphoBlue.sol";
import {IOracle} from "../../../src/interfaces/morpho/IOracle.sol";

/// @title MockMorphoOracle
///
/// @notice Minimal oracle mock with a settable price.
contract MockMorphoOracle is IOracle {
    uint256 internal _price;

    function setPrice(uint256 price_) external {
        _price = price_;
    }

    function price() external view returns (uint256) {
        return _price;
    }
}

/// @title MockMorphoBlue
///
/// @notice Minimal Morpho Blue mock for collateral top-ups.
contract MockMorphoBlue is IMorphoBlue {
    mapping(bytes32 id => MarketParams) internal _params;
    mapping(bytes32 id => Market) internal _markets;
    mapping(bytes32 id => mapping(address user => Position)) internal _positions;

    mapping(bytes32 paramsKey => bytes32 id) internal _idByParamsKey;

    error UnknownMarket();
    error MarketParamsMismatch();

    function setMarket(Id id, MarketParams calldata params, Market calldata market_) external {
        bytes32 rawId = Id.unwrap(id);
        _params[rawId] = params;
        _markets[rawId] = market_;
        _idByParamsKey[_paramsKey(params)] = rawId;
    }

    function setPosition(Id id, address user, Position calldata p) external {
        _positions[Id.unwrap(id)][user] = p;
    }

    function idToMarketParams(Id id) external view returns (MarketParams memory) {
        return _params[Id.unwrap(id)];
    }

    function position(Id id, address user) external view returns (Position memory p) {
        return _positions[Id.unwrap(id)][user];
    }

    function market(Id id) external view returns (Market memory m) {
        return _markets[Id.unwrap(id)];
    }

    function accrueInterest(MarketParams memory) external {}

    function supplyCollateral(MarketParams memory marketParams, uint256 assets, address onBehalf, bytes memory data)
        external
    {
        data;
        bytes32 rawId = _idByParamsKey[_paramsKey(marketParams)];
        if (rawId == bytes32(0)) revert UnknownMarket();

        MarketParams memory stored = _params[rawId];
        if (
            stored.loanToken != marketParams.loanToken || stored.collateralToken != marketParams.collateralToken
                || stored.oracle != marketParams.oracle || stored.irm != marketParams.irm
                || stored.lltv != marketParams.lltv
        ) revert MarketParamsMismatch();

        IERC20(marketParams.collateralToken).transferFrom(msg.sender, address(this), assets);

        Position storage p = _positions[rawId][onBehalf];
        p.collateral = uint128(uint256(p.collateral) + assets);
    }

    function _paramsKey(MarketParams memory mp) internal pure returns (bytes32) {
        return keccak256(abi.encode(mp.loanToken, mp.collateralToken, mp.oracle, mp.irm, mp.lltv));
    }
}

