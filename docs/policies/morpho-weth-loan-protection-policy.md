# `MorphoWethLoanProtectionPolicy`

A single executor policy for **one-shot WETH collateral top-ups** on Morpho Blue when an account's position is at risk of liquidation. Extends `MorphoLoanProtectionPolicy` for markets that use WETH as collateral by wrapping native ETH before supplying.

For shared single executor concepts (executor authorization, signature binding, replay protection, config authentication, nonce cancellation), see `single-executor-policies.md`.

## Summary

The WETH contract address is set at deployment alongside the Morpho address and `MAX_TRIGGER_LTV_RATIO` (all immutable). Each policy deployment targets exactly one Morpho instance and one WETH address.

This policy inherits all semantics from `MorphoLoanProtectionPolicy` — trigger LTV, one-shot execution, one active policy per (account, marketId), post-execute LTV validation — but modifies the call plan to wrap native ETH into WETH before supplying collateral. The account must hold sufficient **native ETH** (not WETH) for the top-up amount.

Install-time validation additionally requires the market's `collateralToken` to match the configured WETH address.

## Config (`LoanProtectionPolicyConfig`)

Same as `MorphoLoanProtectionPolicy`:

| Field | Description |
|---|---|
| `marketId` | Morpho Blue market identifier (must be nonzero, market must exist onchain) |
| `triggerLtv` | Minimum LTV (wad, 1e18 = 100%) required to allow execution |
| `maxTopUpAssets` | Maximum collateral top-up per execution (must be nonzero) |

The full `policyConfig` is `abi.encode(SingleExecutorConfig({ executor }), abi.encode(LoanProtectionPolicyConfig({ marketId, triggerLtv, maxTopUpAssets })))`.

### Install-time validation

All validations from `MorphoLoanProtectionPolicy` apply, plus:

- **Collateral token must be WETH**: fetches `morpho.idToMarketParams(marketId)` and requires `collateralToken == WETH`. Reverts with `CollateralNotWeth(collateralToken, weth)` on mismatch.

## Execution (`TopUpData`)

Same as `MorphoLoanProtectionPolicy`:

| Field | Description |
|---|---|
| `topUpAssets` | Collateral amount to supply (must be > 0, must be ≤ `maxTopUpAssets`) |

## What happens on execute

The policy enforces:

1. `topUpAssets > 0` and `topUpAssets <= maxTopUpAssets`
2. Current LTV ≥ `triggerLtv` (computed from onchain position data and oracle price)
3. Policy instance not already used (one-shot)
4. Standard single executor checks (executor signature, nonce, deadline, config preimage)

Then returns a wallet call plan (3 calls):

1. `WETH.deposit{value: topUpAssets}()` — wraps native ETH into WETH
2. `WETH.approve(morpho, topUpAssets)` — approves Morpho to pull the WETH (no zero-approve needed; WETH is a standard ERC-20)
3. `morpho.supplyCollateral(marketParams, topUpAssets, account, "")` — supplies WETH as collateral

## Post-execute validation

Same as `MorphoLoanProtectionPolicy`: after the account call completes, the policy recomputes the position's LTV and verifies it is below the market's LLTV. If the top-up was insufficient, the entire transaction reverts with `PostTopUpLtvAboveLltv(postTopUpLtv, lltv)` — preserving the one-shot and the account's ETH.

## Constructor

| Parameter | Description |
|---|---|
| `policyManager` | Address of the `PolicyManager` authorized to call hooks |
| `admin` | Address that receives `DEFAULT_ADMIN_ROLE` and `PAUSER_ROLE` |
| `morpho_` | Morpho Blue singleton contract address (must be a deployed contract) |
| `weth_` | WETH contract address for this chain (must be a deployed contract) |
| `maxTriggerLtvRatio_` | Maximum allowed ratio of `triggerLtv` to the market's `lltv` (WAD-scaled) |

## Additional errors

Beyond errors inherited from `MorphoLoanProtectionPolicy`:

| Error | Description |
|---|---|
| `WethNotContract(address weth)` | WETH constructor argument has no deployed code |
| `CollateralNotWeth(address collateralToken, address weth)` | Market's collateral token does not match configured WETH |

## EIP-712 domain

`name = "Morpho WETH Loan Protection Policy"` / `version = "1"`

## Additional storage

Same as `MorphoLoanProtectionPolicy` — inherits all storage (one-shot flag, active policy per market, market key by policy ID). Additionally exposes:

- `WETH` (immutable, public) and `weth()` convenience alias
