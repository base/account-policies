### account-permissions

A modular system for allowing smart contract users the ability to authorize third parties to take specific, well-defined, onchain actions via their account.

### How it works (high level)

- **`src/PolicyManager.sol`**: installs policy instances authorized by the account and executes policy-prepared calldata on the account.
- **`src/PolicyTypes.sol`**: shared type definitions (notably `PolicyTypes.Install`) used by the manager and policies.
- **`src/policies/`**: example policies (each policy defines its own authorization semantics via `authorize(...)` and constructs wallet calldata via `onExecute(...)`).

### Setup

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
