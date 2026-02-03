# `MorphoLendPolicy`

`MorphoLendPolicy` is an AOA policy that authorizes **recurring, executor-signed deposits** into a pinned Morpho vault on behalf of an account, subject to a recurring allowance (budget).

It is designed for “automation with bounded maximums”: the account opts into a fixed vault + limit, and the executor can only deposit within those constraints.

For the AOA family background (envelopes, actors, intent model), see `aoa-policies.md`.

## What it does

MorphoLendPolicy authorizes deposits into a pinned Morpho Vault:

- the **vault address** is fixed by the installed config
- the **receiver** is fixed to the `account`
- each execution supplies an amount (`assets`) and a `nonce`
- deposits are bounded by a recurring allowance (`depositLimit`)

It constructs a wallet call plan that:

1. approves the vault to pull the vault’s `asset()` token for `assets`
2. calls `vault.deposit(assets, account)`

Because the vault pulls exactly `assets` via `transferFrom`, the ERC-20 allowance typically returns to `0` after the deposit.

## Actors

- **Account**: installs with `{executor, vault, depositLimit}`, can always uninstall.
- **Executor**: signs execution intents (EIP-712). Can also uninstall/cancel directly (or by signature via `uninstallData` / `cancelData`).
- **Relayer**: submits `execute(...)` transactions using executor-signed intents.

## Installation config (committed)

`policyConfig` shape:

```
abi.encode(
  AOAConfig({ account, executor }),
  abi.encode(MorphoConfig({ vault, depositLimit }))
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
  - the installed config hash (`policyConfigHash`)
  - `keccak256(actionData)` where `actionData` encodes `{assets, nonce}`
- **Replay protection**: per-`policyId` nonce tracking; each nonce can be used once.
- **Budgeting**: consumes `assets` from a per-`policyId` recurring allowance.

## Execution flow (high level)

1. Caller submits `PolicyManager.execute(policy, policyId, policyConfig, policyData)`.
2. Policy checks the config preimage matches what was installed.
3. Policy verifies an **executor signature** over the execution intent.
4. Policy enforces:
   - `assets > 0`
   - `nonce != 0` and `nonce` unused (replay protection)
   - recurring deposit budget
5. Policy returns a wallet call plan that:
   - approves the vault to spend `assets` of the vault’s asset token
   - calls `vault.deposit(assets, account)`

## Execution payloads

### Action data (`LendData`)

The action data encodes:

- `assets`: amount to deposit, in the vault asset token’s smallest units
- `nonce`: policy-scoped replay protection nonce

### Signature binding

The executor signs an EIP-712 digest computed by the policy over:

- `policyId`
- `account`
- the committed `policyConfigHash` (hash of the installed config preimage)
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

Ergonomic behavior:

- If the config leaves the allowance window timestamps unset (`start == 0 && end == 0`), the policy **binds the allowance window to the policy install window** (`validAfter`/`validUntil`) for a “naturally expiring” budget.
