# AOA policies (Automated Onchain Actions)

AOA (“Automated Onchain Actions”) policies are an opinionated policy family built on top of the generic `Policy` interface (via `AOAPolicy.sol`).

They exist to standardize a common operational pattern:

- a policy instance is installed once by the **account**
- a designated **executor** (or any relayer acting on their behalf) triggers actions over time
- each execution is authorized by an **executor-signed intent**
- policies commonly enforce budgets, replay protection, and guardrails
- policies support practical operational controls (pause, executor-friendly uninstall)

This family is optional: `PolicyManager` remains schema-agnostic and does not “know” AOA schemas. AOA defines a canonical envelope and shared auth model so policies in this family behave consistently.

### Mutable PolicyManager

AOA policies hold a mutable reference to the `PolicyManager`. The admin can update it via `setPolicyManager(address)`, which emits `PolicyManagerUpdated(oldManager, newManager)`. This supports operational upgrades (e.g., migrating to a new manager deployment) without redeploying policies.

## Actors and trust boundaries

- **Account**: installs policies; ultimately executes wallet calls (via the manager). The account can always uninstall installed instances.
- **Executor**: chosen by the account; is the authorization authority for ongoing actions (signs intents). Can be an EOA or contract account.
- **Relayer**: any caller who submits transactions. Relayers are not inherently trusted.

Key property: **relayers do not need to be trusted**. Execution authorization is enforced by the policy (typically via an executor signature over an EIP-712 digest).

## Canonical encoding shapes

AOA owns the internal hook implementations and enforces canonical ABI encoding.

### `policyConfig` (installed commitment)

AOA policies commit to:

`policyConfig = abi.encode(AOAConfig{ executor }, bytes policySpecificConfig)`

The manager binds a policy instance to this config at install time (embedded in the `PolicyBinding`). AOA policies
store a hash of the config and require the full preimage on each execution.

### `executionData` (per execution)

AOA policies commit to:

`executionData = abi.encode(AOAExecutionData{ nonce, deadline, signature }, bytes actionData)`

- `actionData` is policy-defined (e.g., `{amount, ...}`)
- `AOAExecutionData.signature` is validated against an EIP-712 digest computed by the policy
- `AOAExecutionData.nonce` provides replay protection
- `AOAExecutionData.deadline` is optional intent expiry (`0` means “no expiry”)

This makes AOA policies composable: tooling can treat “AOA config + action + signature” as a standard envelope.

AOA policies return early with empty calldata when `executionData` is empty (signaling “no execution” to the manager). This is required because `onExecute` is called during `installWithSignature` and `replaceWithSignature` flows even when no execution is intended. AOA policies may also return `postCallData` from `onExecute`, which the manager forwards to the policy’s `onPostExecute` hook after the account call completes.

## Config authentication strategy (calldata-heavy by default)

AOA policies default to a calldata-heavy model:

- on install, store only `configHash = keccak256(policyConfig)` keyed by `policyId`
- on each execute, the caller supplies `policyConfig` again and the policy verifies it matches the stored hash

This avoids storing large decoded configs onchain while preserving the key invariant:

**every execution is authenticated against the exact config that was installed.**

Policies can still store additional config-derived state at install when needed (e.g., uniqueness constraints), without storing the entire config.

## Executor-signed intents (EIP-712)

Most AOA policies authorize execution by validating an EIP-712 signature from the configured executor over a policy-defined digest.

Common binding properties (policy-defined, but usually includes):

- `policyId` (binds to a specific installed instance)
- `account` (binds to a specific account)
- `policyConfigHash` (binds to the committed config; AOA stores `keccak256(policyConfig)` at install time)
- a hash of the action payload (binds to the specific intent)

Signature verification is done through the manager’s ERC-6492-capable validator, allowing:

- ERC-1271 contract executors
- counterfactual executors (ERC-6492 signatures with side effects)

Replay protection is policy-defined; AOA policies typically include a per-`policyId` nonce in the signed intent and mark nonces as used.

## Operational controls: pause, cancel nonces, uninstall

### Pause / unpause

AOA policies include an admin-controlled pause/unpause (policy-level kill switch) that blocks execution.

### Cancel nonces

The configured executor can cancel one or more nonces for a policy instance via `cancelNonces(policyId, nonces, policyConfig)`. Cancelled nonces are permanently marked as used, preventing any future execution intent that references them. This is useful for revoking pending execution intents without uninstalling the policy. Cancellation is not gated by pause — it is a safety mechanism that should always be available.

### Uninstall with `uninstallData`

The protocol passes an optional opaque blob to the uninstall hook:

- `uninstallData` → `onUninstall(...)`

It can be empty. Policies interpret it however they want; in AOA, it is used to authenticate executor-initiated uninstall
flows via relayer-submitted executor signatures.

Default AOA ergonomics:

- the **account** can always uninstall
- a **relayer** can uninstall if it provides a valid executor signature inside `uninstallData` (optionally with a deadline)

Practical integrator note: for non-account uninstall, AOA policies may require the installed `policyConfig` preimage so
they can decode the configured executor and verify the committed config hash.

### Replacement (`replaceWithSignature`)

During a `replaceWithSignature` flow, the account has already authorized the replacement via their EIP-712 signature. AOA policies therefore skip executor authorization on the uninstall side of a replacement (`_onUninstallForReplace` calls directly into cleanup logic without requiring an executor signature in `replaceData`). This avoids redundant authorization when the account has already blessed the operation.

## EIP-712 domains

AOA signatures are policy-contract-scoped: each policy defines its own EIP-712 `name`/`version` domain.

This prevents a signature intended for one policy contract from being valid on another.

