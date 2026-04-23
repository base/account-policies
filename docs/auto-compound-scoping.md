# Auto-Claim & Compound Policy — Contract Scoping & Open Questions

## Context

Users earning Morpho token rewards through Coinbase's onchain lending (Morpho vaults) must claim those rewards manually today. This policy automates the full loop: claim MORPHO from the Merkl distributor, swap to USDC via a DEX, and deposit back into the user's lending vault — compounding automatically without user intervention.

This is a new policy in the [account-policies](https://github.com/user/account-policies) framework. It inherits from `SingleExecutorAuthorizedPolicy`, giving it executor-signed execution with nonce replay protection, atomic multi-call batching via `CoinbaseSmartWallet.executeBatch`, post-execution validation via `onPostExecute`, and the standard install/uninstall/replace lifecycle. The existing `MorphoLendPolicy` and `MorphoLoanProtectionPolicy` establish the pattern this policy follows.

A legal constraint shapes the design: Coinbase cannot auto-sell users' MORPHO tokens without explicit consent (per the arrangement with Morpho). The policy captures this consent cryptographically at install time via a config flag covered by the user's EIP-712 signature.

---

## Proposed Architecture

### Two contracts, one atomic transaction

**Policy contract** (`MorphoAutoCompoundPolicy`): the on-chain authorization layer. It validates config and executor-signed action data, constructs a 3-call batch for the wallet, enforces the claim-only vs. full-compound consent gate, and runs post-execution slippage validation. It never touches user funds directly.

**Periphery contract** (`AutoCompoundPeriphery`): a stateless, non-upgradeable helper that executes the swap-and-deposit in a single call frame. The wallet approves MORPHO to it; it pulls the tokens, swaps via a hardcoded DEX, observes the actual USDC received, and deposits that exact amount into the vault — minting shares to the user's wallet. It ends every transaction holding zero tokens.

### Why the periphery is necessary

The account-policies framework is deliberately **plan-then-execute**: the policy constructs the complete call plan *before* any calls run, then the PolicyManager executes the plan on the wallet, then the policy verifies the outcome in `onPostExecute`. The policy cannot observe intermediate state between calls.

For this feature, the swap output (how much USDC was received) determines the deposit amount — but the policy doesn't know that value at call-construction time because the swap hasn't happened yet. Without the periphery, the executor would have to guess the deposit amount and pass it in the action data. If the guess is wrong (price moved, claim amount differed), the transaction reverts harmlessly, but the user's rewards don't compound that cycle.

The periphery solves this by collapsing swap + deposit into a single call. Because it executes both steps itself, it can read the actual swap output and pass it directly to `vault.deposit()`. No guessing, no stale amounts.

An alternative considered was adding iterative execution to the core protocol (policy gets callbacks between calls to observe state and decide the next step). This was rejected — it would fundamentally change the security model, introduce reentrant call chains, and make policies far harder to audit. The periphery is the scoped escape hatch for the rare case where calls have data dependencies between them.

---

## End-to-End Flow

### Data sources and responsibilities

| Data | Source | Provided by | When |
|---|---|---|---|
| Merkle proof + cumulative claim amount | Merkl API (`api.merkl.xyz`) | Executor | Fetched before each execution |
| Swap amount (MORPHO to swap) | On-chain: `merklDistributor.claimed(user, MORPHO)` subtracted from cumulative | Executor (computes off-chain) | Included in signed action data |
| Swap routing + minAmountOut | DEX interface hardcoded in periphery; min computed from oracle + config slippage | Policy / periphery (constructed on-chain) | At execution time |
| Vault address | Policy config (pinned at install) | User (signed at install) | Fixed per policy instance |
| Slippage tolerance | Policy config (`maxSlippageBps`) | User (signed at install) | Fixed per policy instance |
| Executor authorization | EIP-712 signature over action data with nonce | Executor | Per-execution |

### Call sequence

```
Executor fetches Merkl proof + computes expected claim delta
Executor signs actionData (claimAmount, claimProof, swapAmountIn)
Executor calls PolicyManager.execute(policy, policyId, policyConfig, executionData)
    │
    ├─ PolicyManager calls policy.onExecute(...)
    │      policy validates executor signature + nonce
    │      policy checks consent mode (convertAndReinvest flag)
    │      policy snapshots account balances for post-execution check
    │      policy constructs Call[] batch and returns it
    │
    ├─ PolicyManager calls wallet.executeBatch(calls):
    │      [Call 1]  wallet → MerklDistributor.claim([wallet], [MORPHO], [amount], [proof])
    │      [Call 2]  wallet → MORPHO.approve(periphery, swapAmountIn)
    │      [Call 3]  wallet → periphery.swapAndDeposit(vault, swapAmountIn, ...)
    │                            periphery pulls MORPHO from wallet
    │                            periphery swaps MORPHO → USDC via hardcoded DEX
    │                            periphery calls vault.deposit(usdcReceived, wallet)
    │                            vault mints shares to wallet
    │
    └─ PolicyManager calls policy.onPostExecute(...)
           policy reads account balances again
           policy computes effective swap rate from deltas
           policy reverts entire tx if rate violates slippage config
```

In **claim-only mode** (`convertAndReinvest == false`), the batch is just Call 1. The policy hard-rejects any action data that includes swap parameters.

### What happens when things go wrong

Every call in the batch is atomic. If any step fails — stale proof, insufficient MORPHO balance, swap slippage exceeded, vault deposit reverts — the entire transaction reverts. No partial state changes, no stuck funds. The executor retries next cycle with fresh data.

### Merkl claiming details

Morpho rewards aren't tracked on-chain per-user in real time. Morpho computes allocations off-chain, builds a merkle tree of cumulative rewards per user, and publishes the root to the Merkl distributor every ~8 hours. Claiming requires a merkle proof obtained from the Merkl API. The executor must integrate with this API to fetch proofs before each execution.

The smart wallet is `msg.sender` for the claim call, which satisfies the Merkl distributor's authorization check (`msg.sender == user`). No operator allowlisting or separate setup transaction is needed.

### Consent model

| Mode | `convertAndReinvest` config flag | Executor capability |
|---|---|---|
| Full compound | `true` | Claim + swap + deposit (may also claim-only on a given execution) |
| Claim-only | `false` | Claim only; policy rejects any swap or deposit |
| No automation | Policy not installed | Nothing |

The config flag is the consent boundary. It's part of `policyConfig`, which is covered by the user's install signature — a cryptographic record of exactly what the user authorized. The policy enforces it as a hard gate, not a suggestion: when the flag is `false`, the policy reverts if the executor attempts a swap.

Upgrading from claim-only to full compound uses `PolicyManager.replace()`: atomically uninstall the old instance and install a new one with `convertAndReinvest == true`, requiring a fresh user signature.

---

## Open Questions

### Must Resolve Before Building

**1. Which DEX?**

The periphery's swap interface is hardcoded to one DEX — the contract knows how to construct the swap call for that specific router. Future DEX support is handled via inheritance (new periphery subclass per DEX, same pattern as `MorphoWethLoanProtectionPolicy` extending `MorphoLoanProtectionPolicy`), so this decision doesn't lock us in permanently. But we need to pick one to ship v1.

Candidates are Uniswap V3 (`exactInputSingle`) and Aerodrome (Base-native). The deciding factor is MORPHO/USDC liquidity depth on Base at the relevant fee tiers. This needs to be checked.

---

**2. Is there a reliable MORPHO/USDC price oracle on Base?**

The policy's post-execution slippage check compares the effective swap rate against a reference price. The strength of that check depends entirely on where the reference comes from.

With a reliable oracle (Chainlink feed, Uniswap V3 TWAP), the policy can enforce `effectiveRate >= oraclePrice * (1 - maxSlippageBps / 10000)` and revert the entire transaction if the swap was unfavorable. Without one, the best the policy can do is a weaker "net-positive" check (vault shares increased, nothing unexpected drained).

Executor-provided reference prices are not acceptable — a compromised executor would control both the swap and the reference.

If no oracle exists, we should evaluate deploying a TWAP oracle as part of this project rather than accepting the weaker check.

---

**3. Is single-vault acceptable for v1?**

Multi-vault pro-rata distribution is significantly more complex. Merkl claims are all-or-nothing per token — you can't split one claim across separate policy instances. Multi-vault requires the periphery to accept a vault list and allocation, on-chain balance reads for ratio computation, and N×(approve + deposit) calls.

If multi-vault is required: the executor could provide the vault list in action data per-execution (avoiding stale config), with the policy validating each vault against a config-level allowlist and checking `vault.balanceOf(account) > 0` to prevent deposits into vaults where the user has no existing position. The periphery would loop over vaults and split the USDC accordingly.

Recommendation is single-vault for v1. If multi-vault is a hard product requirement, it should be scoped as a separate workstream — the periphery design diverges significantly.

---

**4. Budget caps via RecurringAllowance?**

Should the policy enforce a maximum reinvestment amount per period? This limits blast radius if the executor key is compromised — a capped policy can only deposit up to N USDC per week regardless of what the executor signs.

The `RecurringAllowance` library already exists and is used by `MorphoLendPolicy`. Reusing it here is straightforward. Product needs to define sensible defaults that don't throttle legitimate compounding at expected reward accrual rates.

---

**5. Minimum claim threshold**

Should execution be skipped when claimable MORPHO is below some minimum? This avoids spending gas on dust-level claims. Could be a config field (user sets minimum) or an executor-side filter (executor decides when it's worth claiming).

---

**6. Approval cleanup**

Should the policy add a final call to zero out the MORPHO approval to the periphery after execution? The periphery should consume the full approved amount within `swapAndDeposit`, leaving nothing, but an explicit zero-approval is belt-and-suspenders. Marginal gas cost.

---

**7. Claim-only as a separate policy?**

Claim-only mode could live in a separate, simpler policy contract with no swap logic and no periphery dependency, rather than as a config flag in this one. A separate contract is easier to audit and has a smaller surface area for claim-only users. The config flag approach is simpler operationally — one deployment, one policy to manage, mode upgrades via `replace()` stay within the same contract.
