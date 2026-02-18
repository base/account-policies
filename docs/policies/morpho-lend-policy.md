# `MorphoLendPolicy`

`MorphoLendPolicy` is an AOA policy that authorizes **recurring, executor-signed deposits** into a pinned Morpho vault on behalf of an account, subject to a recurring allowance (budget).

It is designed for “automation with bounded maximums”: the account opts into a fixed vault + limit, and the executor can only deposit within those constraints.

For the AOA family background (envelopes, actors, intent model), see `aoa-policies.md`.

## What it does

MorphoLendPolicy authorizes deposits into a pinned Morpho Vault:

- the **vault address** is fixed by the installed config
- the **receiver** is fixed to the `account`
- each execution supplies an amount (`depositAssets`) and an executor-signed intent envelope with a replay-protection nonce
- deposits are bounded by a recurring allowance (`depositLimit`)

It constructs a wallet call plan that:

1. approves the vault to pull the vault’s `asset()` token for `depositAssets`
2. calls `vault.deposit(depositAssets, account)`

Because the vault pulls exactly `depositAssets` via `transferFrom`, the ERC-20 allowance typically returns to `0` after the deposit.

## Actors

- **Account**: installs with `{executor, vault, depositLimit}`, can always uninstall.
- **Executor**: signs execution intents (EIP-712). Uninstallation is authorized via an executor signature (`uninstallData`).
- **Relayer**: submits `execute(...)` transactions using executor-signed intents.

## Installation config (committed)

`policyConfig` shape:

```
abi.encode(
  AOAConfig({ executor }),
  abi.encode(LendPolicyConfig({ vault, depositLimit }))
)
```

Notable install-time invariants:

- `vault != address(0)`

## How it enforces correctness

At execution time it enforces:

- **Pinned destination**: `vault` comes from config and must be nonzero.
- **Executor authorization**: requires a valid executor signature over a typed execution digest binding:
  - `policyId`
  - `account`
  - the installed config hash (`policyConfigHash` (stored at install time))
  - `keccak256(actionData)` where `actionData` encodes `{depositAssets}`
  - an `executionDataHash` derived from `{nonce, deadline, actionDataHash}` (AOA envelope)
- **Replay protection**: per-`policyId` nonce tracking at the AOA layer; each nonce can be used once.
- **Budgeting**: consumes `depositAssets` from a per-`policyId` recurring allowance.

## Execution flow (high level)

1. Caller submits `PolicyManager.execute(policy, policyId, policyConfig, executionData)`.
2. Policy checks the config preimage matches what was installed.
3. Policy verifies an **executor signature** over the execution intent.
4. Policy enforces:
   - `depositAssets > 0`
   - nonce unused (replay protection)
   - recurring deposit budget
5. Policy returns a wallet call plan that:
   - approves the vault to spend `depositAssets` of the vault’s asset token
   - calls `vault.deposit(depositAssets, account)`

## Execution payloads

### Action data (`LendData`)

The action data encodes:

- `depositAssets`: amount to deposit, in the vault asset token’s smallest units
 
Replay protection and optional expiry are provided by the AOA execution envelope (`AOAExecutionData{nonce, deadline, signature}`).

### Signature binding

The executor signs an EIP-712 digest computed by the policy over:

- `policyId`
- `account`
- the committed `policyConfigHash` (stored at install time) (hash of the installed config preimage)
- a hash of the action payload

This binds the signature to:

- a single policy instance (`policyId`)
- a single account
- a single committed config
- a single action intent

## Calldata vs storage

This policy is primarily calldata-heavy for config:

- stores only `configHash` at install (via `AOAPolicy`)
- requires the config preimage each execution (to decode `vault` + `depositLimit`)

It is stateful for enforcement:

- recurring allowance usage is stored onchain
- used nonces are stored onchain

## Budgeting / allowance

The policy uses a `RecurringAllowance` limit (in vault asset units).

The allowance window is always derived from the policy validity window (`validAfter`/`validUntil`) recorded by the manager:

- `start = validAfter`
- `end = validUntil == 0 ? type(uint48).max : validUntil`
