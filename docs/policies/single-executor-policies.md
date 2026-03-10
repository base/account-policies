# single executor policies

single executor policies are an opinionated policy family built on top of the generic `Policy` interface (via `SingleExecutorPolicy.sol`).

They exist to standardize a common operational pattern:

- a policy instance is installed once by the **account**
- a designated **executor** (or any relayer acting on their behalf) triggers actions over time
- each execution is authorized by an **executor-signed intent** (when an executor is configured)
- policies commonly enforce budgets, replay protection, and guardrails
- policies support practical operational controls (pause, executor-friendly uninstall)

This family is optional: `PolicyManager` remains schema-agnostic and does not "know" single executor schemas. The single executor family defines a canonical envelope and shared auth model so policies in this family behave consistently.

### Mutable PolicyManager

single executor policies hold a mutable reference to the `PolicyManager`. The admin can update it via `setPolicyManager(address)`, which emits `PolicyManagerUpdated(oldManager, newManager)`. This supports operational upgrades (e.g., migrating to a new manager deployment) without redeploying policies.

## Actors and trust boundaries

- **Account**: installs policies; ultimately executes wallet calls (via the manager). The account can always uninstall installed instances.
- **Executor**: optionally chosen by the account; is the authorization authority for ongoing actions (signs intents). Can be an EOA or contract account. When `executor` is `address(0)`, no executor consensus is required.
- **Relayer**: any caller who submits transactions. Relayers are not inherently trusted.

Key property: **relayers do not need to be trusted**. Execution authorization is enforced by the policy (typically via an executor signature over an EIP-712 digest when an executor is configured).

## Canonical encoding shapes

The single executor family owns the internal hook implementations and enforces canonical ABI encoding.

### `policyConfig` (installed commitment)

single executor policies commit to:

`policyConfig = abi.encode(SingleExecutorConfig{ executor }, bytes policySpecificConfig)`

The manager binds a policy instance to this config at install time (embedded in the `PolicyBinding`). single executor policies store a hash of the config and require the full preimage on each execution.

### `executionData` (per execution)

single executor policies commit to:

`executionData = abi.encode(SingleExecutorExecutionData{ nonce, deadline, signature }, bytes actionData)`

- `actionData` is policy-defined (e.g., `{amount, ...}`)
- `SingleExecutorExecutionData.signature` is validated against an EIP-712 digest computed by the policy (when an executor is configured)
- `SingleExecutorExecutionData.nonce` provides replay protection
- `SingleExecutorExecutionData.deadline` is optional intent expiry (`0` means "no expiry")

This makes single executor policies composable: tooling can treat "single executor config + action + signature" as a standard envelope.

single executor policies return early with empty calldata when `executionData` is empty (signaling "no execution" to the manager). This is required because `onExecute` is called during `installWithSignature` and `replaceWithSignature` flows even when no execution is intended. single executor policies may also return `postCallData` from `onExecute`, which the manager forwards to the policy's `onPostExecute` hook after the account call completes.

## Config authentication strategy (calldata-heavy by default)

single executor policies default to a calldata-heavy model:

- on install, store only `configHash = keccak256(policyConfig)` keyed by `policyId`
- on each execute, the caller supplies `policyConfig` again and the policy verifies it matches the stored hash

This avoids storing large decoded configs onchain while preserving the key invariant:

**every execution is authenticated against the exact config that was installed.**

Policies can still store additional config-derived state at install when needed (e.g., uniqueness constraints), without storing the entire config.

## Executor-signed intents (EIP-712)

`SingleExecutorAuthorizedPolicy` (which inherits `SingleExecutorPolicy` and always requires executor signatures) authorizes execution by validating an EIP-712 signature from the configured executor over a policy-defined digest.

Common binding properties (policy-defined, but usually includes):

- `policyId` (binds to a specific installed instance)
- `account` (binds to a specific account)
- `policyConfigHash` (binds to the committed config; single executor policies store `keccak256(policyConfig)` at install time)
- a hash of the action payload (binds to the specific intent)

Signature verification is done through the manager's ERC-6492-capable validator, allowing:

- ERC-1271 contract executors
- counterfactual executors (ERC-6492 signatures with side effects)

Replay protection is policy-defined; single executor policies typically include a per-`policyId` nonce in the signed intent and mark nonces as used.

## Operational controls: pause, cancel nonces, uninstall

### Pause / unpause

single executor policies include an admin-controlled pause/unpause (policy-level kill switch) that blocks execution.

### Cancel nonces

The configured executor can cancel one or more nonces for a policy instance via `cancelNonces(policyId, nonces, policyConfig)`. Cancelled nonces are permanently marked as used, preventing any future execution intent that references them. This is useful for revoking pending execution intents without uninstalling the policy. Cancellation is not gated by pause — it is a safety mechanism that should always be available.

### Uninstall with `uninstallData`

The protocol passes an optional opaque blob to the uninstall hook:

- `uninstallData` → `onUninstall(...)`

It can be empty. Policies interpret it however they want; in the single executor family, it is used to authenticate executor-initiated uninstall flows via relayer-submitted executor signatures.

Default single executor ergonomics:

- the **account** can always uninstall
- a **relayer** can uninstall if it provides a valid executor signature inside `uninstallData` (optionally with a deadline)

Practical integrator note: for non-account uninstall, single executor policies may require the installed `policyConfig` preimage so they can decode the configured executor and verify the committed config hash.

### Replacement (`replaceWithSignature`)

During a `replaceWithSignature` flow, the account has already authorized the replacement via their EIP-712 signature. single executor policies therefore skip executor authorization on the uninstall side of a replacement (`_onUninstallForReplace` calls directly into cleanup logic without requiring an executor signature in `replaceData`). This avoids redundant authorization when the account has already blessed the operation.

## EIP-712 domains

single executor signatures are policy-contract-scoped: each policy defines its own EIP-712 `name`/`version` domain.

This prevents a signature intended for one policy contract from being valid on another.

## Contract hierarchy

- `SingleExecutorPolicy.sol` — abstract base providing the canonical encoding, config authentication, nonce management, pause/unpause, and hook scaffolding. The `executor` field on `SingleExecutorConfig` is optional: `address(0)` means no executor consensus is required.
- `SingleExecutorAuthorizedPolicy.sol` — inherits `SingleExecutorPolicy` and always requires a valid executor signature on execution. Use this as the base for policies that must enforce executor authorization.
