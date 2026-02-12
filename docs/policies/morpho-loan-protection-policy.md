# `MorphoLoanProtectionPolicy`

`MorphoLoanProtectionPolicy` is an AOA liquidation-protection policy for Morpho Blue. It authorizes **executor-signed, one-shot collateral top-ups** into a pinned Morpho market when an account’s LTV is high.

For the AOA family background (envelopes, actors, intent model), see `aoa-policies.md`.

## What it does

The installed config pins:

- the Morpho Blue contract
- a specific market (`marketId`)
- a trigger LTV threshold
- a fixed one-time collateral top-up amount (`collateralTopUpAssets`)

Executions top up collateral by exactly `collateralTopUpAssets` (plus optional callback data), but only when:

- the current position is unhealthy (above trigger)
- the executor provides a valid signed intent
- the policy instance has not been used already (one-shot)

## Actors

- **Account**: installs with `{executor, morpho, marketId, triggerLtv, collateralTopUpAssets}`, can always uninstall.
- **Executor**: signs top-up intents (EIP-712). Uninstallation is authorized via an executor signature (`uninstallData`).
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
    collateralTopUpAssets
  }))
)
```

Install-time invariants:

- `morpho != address(0)`
- `marketId != 0`
- `collateralTopUpAssets != 0`
- **Market existence**: fetches `morpho.idToMarketParams(marketId)` and requires nonzero params (loan/collateral token, oracle, irm, and `lltv`) so the market must exist on that Morpho instance
- **Uniqueness**: at most one active policy per `(account, marketId)` (enforced via an `(account, marketId) -> policyId` mapping and a `policyId -> marketId` mapping for cleanup)

## How it enforces correctness

At execution time it enforces:

- **Executor authorization**: validates an executor signature over a typed intent binding:
  - `policyId`
  - `account`
  - the committed config hash (`policyConfigHash`)
  - an `executionDataHash` derived from `{nonce, deadline, actionDataHash}` (AOA envelope)
- **Replay protection**: per-`policyId` nonce tracking at the AOA layer.
- **Signature expiry**: optional `deadline` in the AOA execution envelope (`AOAExecutionData.deadline`).
- **Trigger bound**:
  - computes current LTV from onchain Morpho position and oracle price
  - requires `currentLtv >= triggerLtv`
- **One-shot semantics**: reverts if the policyId was already used, and marks the policyId as used after the first successful execution.
- **Pinned action**: the wallet call plan is pinned to:
  - `approve(collateralToken, morpho, collateralTopUpAssets)`
  - `morpho.supplyCollateral(marketParams, collateralTopUpAssets, account, callbackData)` where `marketParams` is looked up from Morpho by `marketId`

## Execution flow (high level)

1. Caller submits `PolicyManager.execute(policy, policyId, policyConfig, executionData)`.
2. Policy checks the config preimage matches what was installed.
3. Policy verifies an **executor signature** over the top-up intent (EIP-712), including expiry.
4. Policy enforces:
   - `nonce` unused (replay protection)
   - `deadline` (intent expiry, optional)
   - LTV trigger
   - one-shot semantics
5. Policy returns a wallet call plan that:
   - approves Morpho to spend `collateralTopUpAssets` of the collateral token
   - calls `morpho.supplyCollateral(marketParams, collateralTopUpAssets, account, callbackData)` (using `marketParams = morpho.idToMarketParams(marketId)`)

As with standard ERC-20 `transferFrom` flows, approving exactly `collateralTopUpAssets` typically results in the allowance returning to `0` after the call.

## Execution payloads

### Action data (`TopUpData`)

The action data includes:

- `callbackData`: forwarded to Morpho’s callback (optional)

Replay protection and optional expiry are provided by the AOA execution envelope (`AOAExecutionData{nonce, deadline, signature}`).

## Calldata vs storage

This policy is calldata-heavy for config via `AOAPolicy` (config preimage required each execution), but more storage-heavy for invariants:

- stores `configHash` per `policyId` (AOA)
- stores per-`policyId` used nonces
- stores cross-instance mappings to enforce one active policy per market and to support uninstall cleanup
