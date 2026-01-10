# Account Permissions

A modular, wallet-agnostic permission management system for EVM smart accounts. This protocol enables secure delegation of account actions through installable policies, allowing fine-grained control over what authorized parties can do on behalf of smart wallet users.

## Overview

The Account Permissions protocol provides a framework for:

- **Policy-based permissions**: Install policies that define specific actions an authority can execute on behalf of a smart wallet
- **Flexible authorization**: Support for both signature-based and direct-call policy installation/revocation
- **Composable design**: Modular policies and adapters for different use cases (spending, swaps, lending)
- **ERC-6492 support**: Compatible with signatures that include deployment side effects

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PermissionManager                               │
│  - Install/revoke policies via signature or direct call                 │
│  - Execute policy-authorized actions on behalf of accounts              │
│  - EIP-712 typed data signing for secure authorization                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌───────────┐   ┌───────────┐   ┌───────────┐
            │  Policy   │   │  Policy   │   │  Policy   │
            │ (Spend)   │   │  (Swap)   │   │ (Lending) │
            └───────────┘   └───────────┘   └───────────┘
                                                    │
                                            ┌───────┴───────┐
                                            ▼               ▼
                                    ┌───────────┐   ┌───────────┐
                                    │  Adapter  │   │  Adapter  │
                                    │ (Aave V3) │   │  (Other)  │
                                    └───────────┘   └───────────┘
```

## Contracts

### Core

| Contract | Description |
|----------|-------------|
| `PermissionManager.sol` | Central hub for installing, revoking, and executing policies |
| `PermissionTypes.sol` | Shared type definitions for the permission system |
| `PublicERC6492Validator.sol` | ERC-6492 signature validation with side effects support |

### Policies

| Contract | Description |
|----------|-------------|
| `SpendPolicy.sol` | Token spending permissions with allowances, periods, and hooks |
| `CoinbaseSmartWalletSwapPolicy.sol` | Constrained token swap execution with slippage protection |
| `CoinbaseSmartWalletSingleCallPolicy.sol` | Simple ETH transfer policy with value limits |
| `LendingPolicy.sol` | DeFi lending operations with health factor enforcement |

### Adapters

| Contract | Description |
|----------|-------------|
| `AaveV3Adapter.sol` | Aave V3 protocol adapter for lending operations |
| `ILendingAdapter.sol` | Interface for lending protocol adapters |

### Spend Hooks

| Contract | Description |
|----------|-------------|
| `SpendHook.sol` | Interface for spend permission preparation hooks |
| `ERC20SpendHook.sol` | ERC20 approval preparation for spending |
| `NativeTokenSpendHook.sol` | Native ETH transfer preparation |
| `MagicSpendSpendHook.sol` | Integration with MagicSpend paymaster |
| `SubAccountSpendHook.sol` | Sub-account token transfer handling |

## Installation

```bash
# Clone the repository
git clone https://github.com/AdekunleBamz/account-permissions.git
cd account-permissions

# Install dependencies (including submodules)
git submodule update --init --recursive

# Build
forge build
```

## Usage

### Build

```bash
forge build
```

### Test

```bash
forge test
```

### Format

```bash
forge fmt
```

### Gas Snapshots

```bash
forge snapshot
```

## Key Concepts

### Policy Installation

Policies are installed by the account owner through either:
1. **Signature-based**: Sign an EIP-712 typed message authorizing the policy
2. **Direct call**: Call `installPolicy` directly from the smart wallet

```solidity
struct Install {
    address account;       // The smart wallet address
    address policy;        // The policy contract to install
    bytes32 policyConfigHash; // Hash of policy-specific configuration
    uint48 validAfter;     // Policy activation timestamp
    uint48 validUntil;     // Policy expiration timestamp
    uint256 salt;          // Unique identifier for the policy instance
}
```

### Policy Execution

Once installed, an authority (defined by the policy) can execute actions:

```solidity
function execute(
    PermissionTypes.Install calldata install,
    bytes calldata policyConfig,
    bytes calldata policyData,
    uint256 execNonce,
    uint48 deadline,
    bytes calldata authoritySig
) external;
```

### Spend Permissions

The `SpendPolicy` enables recurring spending allowances:

- **Allowance**: Maximum amount spendable per period
- **Period**: Time window for allowance reset (e.g., daily, weekly)
- **Start/End**: Permission validity window
- **Hooks**: Customizable preparation logic for different token types

## Security Considerations

- Policies should be carefully audited before installation
- Authority keys should be secured appropriately for their permission scope
- Health factor checks in lending policies provide liquidation protection
- Signature replay is prevented through nonces and deadline enforcement

## Dependencies

This project uses the following dependencies:

- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) - Security utilities and token standards
- [Solady](https://github.com/vectorized/solady) - Gas-optimized Solidity utilities
- [Coinbase Smart Wallet](https://github.com/coinbase/smart-wallet) - Smart wallet implementation
- [MagicSpend](https://github.com/coinbase/magicspend) - Paymaster integration

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and code is formatted before submitting PRs.

```bash
# Run tests
forge test

# Format code
forge fmt

# Check for issues
forge build --force
```
