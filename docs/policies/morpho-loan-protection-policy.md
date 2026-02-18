# `MorphoLoanProtectionPolicy`

An AOA policy for **one-shot collateral top-ups** on Morpho Blue when an account's position is at risk of liquidation.

For shared AOA concepts (executor authorization, signature binding, replay protection, config authentication, nonce cancellation), see `aoa-policies.md`.

## Summary

The Morpho Blue address is set at deployment (immutable). Each policy deployment targets exactly one Morpho instance.

The account commits to a specific market, a trigger LTV, and a max top-up amount. If the account's position exceeds the trigger LTV, the executor can supply collateral on the account's behalf — once.

## Config (`LoanProtectionPolicyConfig`)

| Field | Description |
|---|---|
| `marketId` | Morpho Blue market identifier (must be nonzero, market must exist onchain) |
| `triggerLtv` | Minimum LTV (wad, 1e18 = 100%) required to allow execution |
| `maxTopUpAssets` | Maximum collateral top-up per execution (must be nonzero) |

The full `policyConfig` is `abi.encode(AOAConfig({ executor }), abi.encode(LoanProtectionPolicyConfig({ marketId, triggerLtv, maxTopUpAssets })))`.

### Install-time validation

- Market must exist: fetches `morpho.idToMarketParams(marketId)` and requires all params (loan token, collateral token, oracle, irm, lltv) to be nonzero.
- **One active policy per market**: at most one active policy per `(account, marketId)`. Enforced via a mapping; cleaned up on uninstall.

## Execution (`TopUpData`)

| Field | Description |
|---|---|
| `topUpAssets` | Collateral amount to supply (must be > 0, must be ≤ `maxTopUpAssets`) |

## What happens on execute

The policy enforces:

1. `topUpAssets > 0` and `topUpAssets <= maxTopUpAssets`
2. Current LTV ≥ `triggerLtv` (computed from onchain position data and oracle price)
3. Policy instance not already used (one-shot)
4. Standard AOA checks (executor signature, nonce, deadline, config preimage)

Then returns a wallet call plan:

1. `approve(collateralToken, morpho, topUpAssets)`
2. `morpho.supplyCollateral(marketParams, topUpAssets, account, "")` where `marketParams = morpho.idToMarketParams(marketId)`

The approval typically returns to zero after the supply.

## LTV computation

Current LTV is derived onchain:

```
currentLtv = (borrowAssets * 1e18) / collateralValue
```

Where:
- `borrowAssets = (position.borrowShares * market.totalBorrowAssets) / market.totalBorrowShares` (rounded up)
- `collateralValue = (position.collateral * oracle.price()) / 1e36`

Reverts if collateral value rounds to zero (prevents division by zero and nonsensical LTV).

## Additional storage

Beyond standard AOA state (config hash, used nonces):

- Per-`policyId` one-shot used flag
- `(account, marketId) → policyId` mapping (uniqueness constraint)
- `policyId → marketKey` mapping (for uninstall cleanup)
