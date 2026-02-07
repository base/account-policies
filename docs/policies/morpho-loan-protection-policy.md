# `MorphoLoanProtectionPolicy`

`MorphoLoanProtectionPolicy` is an AOA liquidation-protection policy for Morpho Blue. It authorizes **executor-signed collateral top-ups** into a pinned Morpho market when an account’s LTV is high.

It is meant to support automation/relaying while hard-enforcing market pinning, LTV constraints, and a recurring budget.

For the AOA family background (envelopes, actors, intent model), see `aoa-policies.md`.

## What it does

The installed config pins:

- the Morpho Blue contract
- a specific market (`marketId`)
- risk thresholds:
  - trigger LTV
  - min/max post-protection LTV bounds
- a recurring collateral budget (`collateralLimit`)

Executions top up collateral by `collateralAssets` (plus optional callback data), but only when:

- the current position is unhealthy (above trigger)
- the projected post-top-up LTV is within bounds
- the recurring collateral budget allows it
- the executor provides a valid signed intent

## Actors

- **Account**: installs with `{executor, morpho, marketId, thresholds, budget}`, can always uninstall.
- **Executor**: signs top-up intents (EIP-712). Can also uninstall/cancel directly (or by signature via `uninstallData` / `cancelData`).
- **Relayer**: submits `execute(...)` transactions using executor-signed intents.

## Installation config (committed)

`policyConfig` shape:

```
abi.encode(
  AOAConfig({ account, executor }),
  abi.encode(LoanProtectionPolicyConfig({
    morpho,
    marketId,
    triggerLtv,
    minPostProtectionLtv,
    maxPostProtectionLtv,
    collateralLimit
  }))
)
```

Install-time invariants:

- `morpho != address(0)`
- `marketId != 0`
- **Market existence**: fetches `morpho.idToMarketParams(marketId)` and requires nonzero params (loan/collateral token, oracle, irm, and `lltv`) so the market must exist on that Morpho instance
- **Uniqueness**: at most one active policy per `(account, marketId)` (enforced via an `(account, marketId) -> policyId` mapping and a `policyId -> marketId` mapping for cleanup)

## How it enforces correctness

At execution time it enforces:

- **Executor authorization**: validates an executor signature over a typed intent with:
  - an outer execution digest binding `(policyId, account, installed config hash, executionDataHash)`
  - an inner structured `TopUpData` binding `(collateralAssets, nonce, deadline, callbackDataHash)`
- **Replay protection**: per-`policyId` nonce tracking.
- **Signature expiry**: optional `deadline` inside `TopUpData`.
- **Trigger + postcondition bounds**:
  - computes current LTV from onchain Morpho position and oracle price
  - computes projected LTV after applying `collateralAssets`
  - requires `currentLtv >= triggerLtv`
  - requires `projectedLtv` is within `[minPostProtectionLtv, maxPostProtectionLtv]`
- **Budgeting**: consumes `collateralAssets` from a per-`policyId` recurring collateral allowance.
- **Pinned action**: the wallet call plan is pinned to:
  - `approve(collateralToken, morpho, collateralAssets)`
  - `morpho.supplyCollateral(marketParams, collateralAssets, account, callbackData)` where `marketParams` is looked up from Morpho by `marketId`

## Execution flow (high level)

1. Caller submits `PolicyManager.execute(policy, policyId, policyConfig, executionData)`.
2. Policy checks the config preimage matches what was installed.
3. Policy verifies an **executor signature** over the top-up intent (EIP-712), including expiry.
4. Policy enforces:
   - `collateralAssets > 0`
   - `nonce != 0` and `nonce` unused (replay protection)
   - `deadline` (intent expiry)
   - LTV trigger + projected LTV bounds
   - recurring collateral budget
5. Policy returns a wallet call plan that:
   - approves Morpho to spend `collateralAssets` of the collateral token
   - calls `morpho.supplyCollateral(marketParams, collateralAssets, account, callbackData)` (using `marketParams = morpho.idToMarketParams(marketId)`)

As with standard ERC-20 `transferFrom` flows, approving exactly `collateralAssets` typically results in the allowance returning to `0` after the call.

## Execution payloads

### Action data (`TopUpData`)

The action data includes:

- `collateralAssets`: collateral-token smallest units
- `nonce`: replay protection
- `deadline`: signature expiry (unix timestamp; `0` may be treated as “no expiry” by convention)
- `callbackData`: forwarded to Morpho’s callback (optional)

### Signature binding (two-layer hash)

The policy signs over the semantic fields of `TopUpData` rather than the raw ABI bytes:

- It hashes `TopUpData` as:
  - `callbackDataHash = keccak256(callbackData)`
  - `topUpDataHash = keccak256(abi.encode(TOP_UP_DATA_TYPEHASH, collateralAssets, nonce, deadline, callbackDataHash))`
- Then it computes an outer execution digest over:
  - `policyId`
  - `account`
  - committed `policyConfigHash`
  - `topUpDataHash`

This avoids ambiguity and makes the signature intent explicit.

## Calldata vs storage

This policy is calldata-heavy for config via `AOAPolicy` (config preimage required each execution), but more storage-heavy for invariants:

- stores `configHash` per `policyId` (AOA)
- stores per-`policyId` recurring allowance usage
- stores per-`policyId` used nonces
- stores cross-instance mappings to enforce one active policy per market and to support uninstall cleanup

## Budgeting / allowance

The policy uses a `RecurringAllowance` limit (in collateral-token units).

Ergonomic behavior:

- If the config leaves the allowance window timestamps unset (`start == 0 && end == 0`), the policy **binds the allowance window to the policy install window** (`validAfter`/`validUntil`).
