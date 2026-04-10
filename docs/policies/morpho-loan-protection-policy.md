# `MorphoLoanProtectionPolicy`

A single executor policy for **one-shot collateral top-ups** on Morpho Blue when an account's position is at risk of liquidation.

For shared single executor concepts (executor authorization, signature binding, replay protection, config authentication, nonce cancellation), see `single-executor-policies.md`.

## Summary

The Morpho Blue address and a `MAX_TRIGGER_LTV_RATIO` are set at deployment (both immutable, Morpho validated as a deployed contract). Each policy deployment targets exactly one Morpho instance.

The account commits to a specific market, a trigger LTV, and a max top-up amount. If the account's position exceeds the trigger LTV, the executor can supply collateral on the account's behalf — once. A post-execution check ensures the top-up actually brought the position below the market's liquidation LTV; if not, the entire transaction reverts, preserving the one-shot and the account's collateral.

## Config (`LoanProtectionPolicyConfig`)

| Field | Description |
|---|---|
| `marketId` | Morpho Blue market identifier (must be nonzero, market must exist onchain) |
| `triggerLtv` | Minimum LTV (wad, 1e18 = 100%) required to allow execution |
| `maxTopUpAssets` | Maximum collateral top-up per execution (must be nonzero) |

The full `policyConfig` is `abi.encode(SingleExecutorConfig({ executor }), abi.encode(LoanProtectionPolicyConfig({ marketId, triggerLtv, maxTopUpAssets })))`.

### Install-time validation

- Market must exist: fetches `morpho.idToMarketParams(marketId)` and requires all params to be nonzero. Additionally verifies `market.lastUpdate != 0` (Morpho sets this on `createMarket`; zero means the market was never created via the canonical path).
- **`triggerLtv` must be nonzero**: a zero trigger would make the `currentLtv < triggerLtv` check always false, allowing unconditional execution regardless of position health.
- **Trigger LTV below proportional ceiling**: `triggerLtv` must be strictly less than `lltv * MAX_TRIGGER_LTV_RATIO / 1e18` (and also strictly less than `lltv`). `MAX_TRIGGER_LTV_RATIO` is set at deployment (e.g., 0.95e18 means `triggerLtv` must be below 95% of the market's `lltv`). This ensures a meaningful reaction window before the position becomes liquidatable.
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
4. Standard single executor checks (executor signature, nonce, deadline, config preimage)

Then returns a wallet call plan:

1. `approve(collateralToken, morpho, 0)` (zero-approve for non-standard tokens like USDT)
2. `approve(collateralToken, morpho, topUpAssets)`
3. `morpho.supplyCollateral(marketParams, topUpAssets, account, "")` where `marketParams = morpho.idToMarketParams(marketId)`

The approval typically returns to zero after the supply.

## Post-execute validation

After the account call completes, the policy's `onPostExecute` hook recomputes the position's LTV and verifies it is below the market's LLTV. If the top-up was insufficient to bring the position out of the liquidation zone (e.g., due to price movement between the executor's signature and transaction inclusion), the entire transaction reverts with `PostTopUpLtvAboveLltv(postTopUpLtv, lltv)` — preserving the one-shot and the account's collateral.

## LTV computation

The policy calls `morpho.accrueInterest(marketParams)` before reading any market state to ensure totals reflect the latest interest accrual. Current LTV is then derived onchain:

```
currentLtv = (borrowAssets * 1e18) / collateralValue
```

Where:
- `borrowAssets = SharesMathLib.toAssetsUp(position.borrowShares, market.totalBorrowAssets, market.totalBorrowShares)` (rounded up, using Morpho's virtual-shares math)
- `collateralValue = (position.collateral * oracle.price()) / 1e36`

Reverts if collateral value rounds to zero (prevents division by zero and nonsensical LTV).

## Additional storage

Beyond standard single executor state (config hash, used nonces):

- Per-`policyId` one-shot used flag
- `activePolicyByMarket`: `(account, marketId) → policyId` mapping (uniqueness constraint, public)
- `marketKeyByPolicyId`: `policyId → marketKey` mapping (for uninstall cleanup, public)
