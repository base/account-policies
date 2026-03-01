// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {MarketParams} from "../../src/interfaces/morpho/BlueTypes.sol";
import {MorphoLoanProtectionPolicy} from "../../src/policies/MorphoLoanProtectionPolicy.sol";

/// @title MorphoLoanProtectionHarness
///
/// @notice Test harness that exposes internal `MorphoLoanProtectionPolicy` functions for direct unit testing.
contract MorphoLoanProtectionHarness is MorphoLoanProtectionPolicy {
    constructor(address policyManager, address admin, address morpho_)
        MorphoLoanProtectionPolicy(policyManager, admin, morpho_)
    {}

    function exposed_computeCurrentLtv(
        LoanProtectionPolicyConfig memory config,
        MarketParams memory marketParams,
        address account
    ) external returns (uint256) {
        return _computeCurrentLtv(config, marketParams, account);
    }

    function exposed_clearInstallState(bytes32 policyId, address account) external {
        _clearInstallState(policyId, account);
    }

    function setActivePolicyByMarket(address account, bytes32 marketKey, bytes32 policyId) external {
        activePolicyByMarket[account][marketKey] = policyId;
    }

    function setMarketKeyByPolicyId(bytes32 policyId, bytes32 marketKey) external {
        marketKeyByPolicyId[policyId] = marketKey;
    }
}
