# `MoiraiDelegate`

A single executor policy for **one-shot deferred execution** of a fixed wallet call, gated by a time-lock and/or executor consensus signature.

For shared single executor concepts (executor authorization, signature binding, replay protection, config authentication, nonce cancellation), see `single-executor-policies.md`.

## Summary

The account commits to a single fixed call (`target`, `value`, `callData`) at install time. Execution is permitted once, after at least one of two conditions is met:

1. The configured `unlockTimestamp` has passed (time-lock), or
2. The configured `consensusSigner` has co-signed the execution intent.

Both conditions can be combined. If no consensus signer is set (time-lock-only mode), any non-empty `executionData` triggers the call once the time-lock is met — content is ignored.

## Config (`MoiraiConfig`)

| Field | Description |
|---|---|
| `target` | Address to call on the account's behalf |
| `value` | ETH value (wei) to forward with the call |
| `callData` | Calldata to pass to `target` |
| `unlockTimestamp` | Earliest block timestamp (seconds) at which execution is allowed. `0` means no time-lock. |
| `consensusSigner` | Address authorized to co-sign execution. `address(0)` means no consensus required. Must match `SingleExecutorConfig.executor`. |

The full `policyConfig` is `abi.encode(SingleExecutorConfig({ executor }), abi.encode(MoiraiConfig({ target, value, callData, unlockTimestamp, consensusSigner })))`.

### Install-time validation

- `consensusSigner` must equal `executor` in the outer `SingleExecutorConfig`.
- At least one of `unlockTimestamp > 0` or `consensusSigner != address(0)` must be set (`NoConditionSpecified` otherwise).

## Execution data

**With consensus signer** (`consensusSigner != address(0)`):

`executionData = abi.encode(SingleExecutorExecutionData{ nonce, deadline, signature }, bytes actionData)`

Standard single executor envelope — the signature is validated against an EIP-712 digest. Nonce is consumed and deadline is checked.

**Without consensus signer** (time-lock only):

Any non-empty `bytes` triggers execution once the time-lock is met. Content is ignored entirely — only the non-zero length is checked.

**Empty `executionData`**: always a no-op — does not consume the one-shot lock. Callers who want to trigger the policy must supply non-empty `executionData`.

## What happens on execute

1. If `executionData` is empty, return early (no-op; lock not consumed).
2. Verify `policyConfig` preimage matches the stored config hash.
3. Revert with `AlreadyExecuted(policyId)` if already executed.
4. If `unlockTimestamp > 0`, revert with `UnlockTimestampNotReached(currentTimestamp, unlockTimestamp)` if `block.timestamp < unlockTimestamp`.
5. If `consensusSigner != address(0)`, decode `SingleExecutorExecutionData` from `executionData` and validate the executor signature (nonce consumed, deadline checked).
6. Set `_executed[policyId] = true`.
7. Return `CoinbaseSmartWallet.execute(target, value, callData)` as the account call.

The actual call parameters (`target`, `value`, `callData`) are always taken from `policyConfig`, never from `executionData`.

## One-shot semantics

Each policy instance may only execute once. The `_executed[policyId]` flag is set on first execution and is never cleared (unless the policy is uninstalled). Cancellation is simply uninstalling the policy.

## Uninstall

Only the bound account may uninstall (`caller != account` reverts with `Unauthorized`). On uninstall or replacement, `_executed` and `_configHashByPolicyId` are cleared.

During a `replaceWithSignature` flow, the account has already authorized the operation — executor authorization is skipped on the uninstall side.

## EIP-712 domain

`name = "Moirai Delegate"` / `version = "1"`

## Additional storage

Beyond standard single executor state (config hash, used nonces):

- Per-`policyId` executed flag (`_executed`, private); readable via `isExecuted(bytes32 policyId) external view returns (bool)`
