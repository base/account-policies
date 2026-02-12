# Account Policies

Account Policies are a wallet-agnostic onchain mechanism for installing **constrained capability modules** (“policies”) on an account and executing policy-prepared actions via the account.

The protocol is intentionally split into:

* **`PolicyManager`**: a minimal orchestrator that tracks policy instances, verifies policy installation authorization, tracks lifecycle transitions and enforces invariants, and mediates policy execution on user accounts.
    - The `PolicyManager` must be an execution-enabled owner on the user smart contract wallet.
    - This is the core trust anchor: the account delegates execution capability to the manager, and the manager delegates *policy-specific* authorization to policies.
* **`Policy`**: a minimal hook interface that policy contracts implement to define authorization semantics and build a calldata payload that will serve as the wallet's call plan. 
    - Policies are modular and extensible, and are wallet-interface-aware (because they emit wallet call plans). The `PolicyManager` has no prior or fixed knowledge of specific policies.

The core idea is to keep the manager stable and generic, while letting policies express the application-specific logic: what’s allowed, under what conditions, and how to execute it safely.

![Account Policies diagram](docs/diagrams/AccountPoliciesDiagram.png)

## What this enables

Policies let an account pre-authorize *specific kinds of future actions* (often executed by a relayer/executor) without giving blanket control.

Possible patterns include:

* automation (recurring constrained actions)  
* delegated execution (third-party calls authorized by signatures/roles)  
* conditional actions (e.g., only when health factor is low)  
* budgeted actions (recurring limits)



## Core concepts

### Policy instance and `policyId`

A **policy instance** is a specific authorization of a specific policy contract for a specific account, under a specific binding. Each instance is identified by a deterministic `policyId`, derived from a signed binding:

```
PolicyBinding {
  account,
  policy,
  validAfter,
  validUntil,
  salt,
  policyConfigHash
}
```

`policyId = hash(binding)`.

**`policyId` names the authorization instance**, not “the policy in general.” Change any binding field (including `salt`) and you get a new instance ID.

### Config and execution payloads

* **`policyConfig`**: opaque config bytes (preimage), decoded in the context of a specific policy. The manager authenticates it at install time (and for pre-install uninstallation) via `keccak256(policyConfig) == policyConfigHash`.  
* **`executionData`**: opaque per-execution payload bytes. Policies interpret and authenticate these.
* **`uninstallData`**: optional opaque bytes passed to policy uninstall hooks for policy-defined authorization (e.g., executor signatures). This can be empty when not needed.

The manager does not impose a schema on either as this is left up to the interpreting policy.

### Validity windows

Bindings include `validAfter` / `validUntil`. The manager enforces these windows at install time and execution time.

A policy can treat these fields as pure protocol gating, or incorporate them into higher-level semantics (e.g. budgets bound to the install window).


## Lifecycle and ergonomics

### Install

A policy instance can be installed either:

* by a direct call from the account, or  
* via an account signature (ERC-6492-compatible, side effects allowed).

**Idempotent installs:** installing an already-installed `(policy, policyId)` is a no-op. The manager does not emit additional lifecycle transitions or re-run hooks.

Why:

* avoids brittle “first installer wins” races  
* prevents replayed signatures from retriggering policy-side effects  
* ensures policy hooks run exactly once per lifecycle transition

### Execute

To execute an action under an installed policy instance, callers invoke:

`PolicyManager.execute(policy, policyId, policyConfig, executionData)`

The execution flow is:

manager → policy → manager → account → manager → policy → manager

A policy authorizes the execution and returns:

* calldata to call on the account (the “actions”)  
* optional calldata to call back into the policy (post-call verification/steps)

This pattern enables strong postconditions (balance deltas, state checks, approval resets) without requiring the manager to understand policy-specific semantics.
For example: a swap policy can snapshot balances before the wallet call, then verify `tokenOutDelta >= minOut` and reset approvals in the post-call.

### Uninstall

Uninstall revokes an **installed** policy instance and tombstones it permanently.

Importantly, uninstall is addressed by **instance identifier**, not by a full binding:

- `uninstall(UninstallPayload{policy, policyId, ...})` supports a policyId-mode that addresses the instance by `(policy, policyId)` where `policyId = hash(binding)`.
- It does *not* take the full `PolicyBinding` fields; those fields may not be available to relayers/indexers once an instance is installed.

The manager provides one global guarantee: **The account can always uninstall its own installed policy instances.**

If a policy’s uninstall hook reverts, the manager only allows that revert to block uninstallation for non-account callers. This prevents policies from trapping the account.
In other words: policies can set the terms of third-party uninstalls, but they can never make uninstall impossible for the user account.

### Pre-install uninstallation

Uninstallation can also be used to revoke (tombstone) an installation intent **before** the policy is installed.

In binding-mode (when the instance is not installed yet), the manager:

* computes `policyId = hash(binding)`  
* verifies `keccak256(policyConfig) == binding.policyConfigHash`  
* calls `policy.onUninstall(...)` for policy-defined authorization  
* tombstones the `policyId` permanently and emits the uninstall event

### Replace

Replacement atomically uninstalls an installed policy instance and installs a new one (authorized by account signature).

Replacement exists as a standardized atomic migration mechanism so integrators do not need to reinvent their own batching/migration flows, and so policies can rely on consistent lifecycle invariants during transitions.

### Install + optional execute convenience

The protocol includes an install+optional-execute convenience via `installWithSignature(..., executionData)`.

This **does not bind** the installation signature to the `executionData` (i.e., it is not an atomic intent-binding
signature). Policies MUST enforce their own execution authorization semantics.

---

## Trust and responsibility boundaries

A core goal of the protocol is to make the trust boundary explicit.

### What `PolicyManager` is responsible for

The manager is the generic, minimal enforcement layer:

* computes deterministic `policyId` from the binding  
* validates account signatures (or calls) for installs/replacements (ERC-6492 capable)  
* enforces config hash matching at install and pre-install uninstallation  
* enforces `validAfter` / `validUntil` at install and execute  
* maintains policy instance liveness state (installed / uninstalled)  
* enforces sticky tombstones (uninstallation permanently kills a `policyId`)  
* mediates all policy hooks and provides a consistent execution environment  
* guarantees “account can always uninstall installed instances”

### What policies are responsible for

Policies define all policy-specific semantics:

* execution authorization (who can execute and under what conditions)  
* decoding and validating `policyConfig` and `executionData`  
* replay protection and nonce discipline for executions  
* policy-specific limits and invariants (budgets, pinning, slippage bounds, thresholds, etc.)  
* any policy-specific state (stored config fields, budgets, uniqueness constraints, nonces)  
* optional third-party uninstallation rules (using `uninstallData`)  
* optional post-call validation/cleanup via the “policy → account → policy” sandwich

### Config handling strategy is explicitly policy-defined

The protocol supports both:

* **Calldata-heavy** policies: require callers to provide the config preimage on each execution, and verify it matches what was installed (cheap install; repeated calldata costs).  
* **Storage-heavy** policies: store needed config-derived data at install, and allow empty config on execute (more upfront state; cheaper repeated execution).

There is no universal best choice; it depends on config size, expected number of executions per install, and chain fee dynamics.

The manager stays neutral; policies decide.

---

## Notes on policy implementation

Policies implement the minimal `Policy` hooks:

* `onInstall`: validate installation and optionally initialize policy state  
* `onUninstall`: authorize uninstall (including pre-install tombstoning) and optionally clean up policy state  
* `onExecute`: authorize execution and return a call plan

Policies are only callable by the manager, which keeps the trust boundary clean and prevents integrators from bypassing lifecycle logic.

---

## Setup

This repo uses git submodules for dependencies (in `lib/`).

Clone with submodules:

```shell
git clone --recurse-submodules <repo>
```

If you already cloned without submodules:

```shell
git submodule update --init --recursive
```

### Build

```shell
forge build
```

### Test

```shell
forge test --offline
```

### Format

```shell
forge fmt
```