# `MorphoLendPolicy`

An AOA policy for **recurring, budgeted deposits** into a pinned Morpho vault.

For shared AOA concepts (executor authorization, signature binding, replay protection, config authentication, nonce cancellation), see `aoa-policies.md`.

## Summary

The account commits to a vault and a recurring deposit budget at install time. The executor can trigger deposits within those constraints. Each execution deposits a specified amount of the vault's underlying asset on behalf of the account.

## Config (`LendPolicyConfig`)

| Field | Description |
|---|---|
| `vault` | Morpho vault to deposit into (must be nonzero) |
| `depositLimit.allowance` | Maximum deposit amount per recurring period |
| `depositLimit.period` | Period length in seconds |

The full `policyConfig` is `abi.encode(AOAConfig({ executor }), abi.encode(LendPolicyConfig({ vault, depositLimit })))`.

## Execution (`LendData`)

| Field | Description |
|---|---|
| `depositAssets` | Amount to deposit (vault asset token units, must be > 0) |

## What happens on execute

The policy enforces:

1. `depositAssets > 0`
2. Recurring budget not exceeded
3. Standard AOA checks (executor signature, nonce, deadline, config preimage)

Then returns a wallet call plan:

1. `approve(vault.asset(), vault, depositAssets)`
2. `vault.deposit(depositAssets, account)`

The vault pulls tokens via `transferFrom`, so the approval typically returns to zero after the deposit.

## Budgeting

Deposits are bounded by a `RecurringAllowance` (in vault asset units). The allowance window is derived from the policy's validity window:

- `start = validAfter`
- `end = validUntil == 0 ? type(uint40).max : validUntil`

## Additional storage

Beyond standard AOA state (config hash, used nonces):

- Recurring allowance usage per `policyId`
