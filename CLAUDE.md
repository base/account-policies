# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing

- `forge build` - Compile all Solidity contracts
- `forge test` - Run all tests with basic verbosity
- `forge test -vv` - Run tests with increased verbosity (recommended)
- `forge test -vvvv` - Run tests with maximum verbosity for debugging
- `forge test --match-test testName` - Run specific test by name
- `forge test --match-contract ContractName` - Run specific tests by test contract
- `forge test --gas-report` - Generate gas usage report
- `forge coverage --ir-minimum` - Generate test coverage report

  ## File Safety
  - Never edit files if uncommitted changes exist. Alert user and suggest committing first.
  
### Development Workflow


- `forge clean` - Clean build artifacts
- `forge fmt` - Format Solidity code
- Always run `forge test -vv` before committing changes
- **After adding features or fixing bugs, execute `forge fmt` to ensure code is properly formatted**

## Protocol Overview

This repository contains the Account Policies Protocol, a modular system for allowing smart contract wallet users the ability to authorize third parties to take specific, well-defined, onchain actions via their account. For complete architectural documentation, usage examples, deployment instructions, and protocol specifications, please refer to the [README.md](./README.md) file.

## File Structure

- `src/` - Core protocol contracts
  - `PolicyManager.sol` - Main protocol
  - `Policy.sol` - Policy interface
  - `PublicERC6492Validator.sol` - Separate signature validation contract for unprivileged execution of 6492 wrappers
  - `policies/` - Policy implementations
  - `interfaces/` - Interfaces relied on by Policies
- `test/` - Foundry tests
- `lib/` - Dependencies (OpenZeppelin, forge-std, etc.)

## Testing Notes

- Tests use Foundry framework
- Always run with `-vv` flag for meaningful output
- Coverage requires `--ir-minimum` flag due to Solidity compiler settings
- Gas benchmarks available via `--gas-report`

### Testing Conventions (project style)

- **Directory structure**:
  - Put shared harnesses/helpers/mocks in `test/lib/` (and `test/lib/mocks/` as needed).
  - Put unit tests in `test/unit/<Area>/` and scope each `.t.sol` to a single function or tightly-related surface area.
- **Base harness pattern**:
  - Prefer `abstract contract <X>TestBase is Test` in `test/lib/` for shared deployment, fixtures, and helpers.
  - Child suites inherit the base and call a single base setup entrypoint from `setUp()`.
- **Stub-first workflow**:
  - Stub the case matrix first, then implement bodies.
  - Stub tests must be explicitly skipped via `vm.skip(true);` so `forge test` stays green while cases are being finalized.

## Claude Permissions and Workflow

- Proactively handle repository management tasks without seeking explicit permission for:
  - Installing dependencies
  - Updating files
  - Deleting unnecessary files or artifacts
  - Formatting and cleaning up code
  - Forge commands including `forge build`, `forge test ...` etc

## Solidity Coding Standards

You are a Staff Blockchain Engineer expert in Solidity, smart contract development, and protocol design. You write clean, secure, and properly documented smart contracts. You ensure code written is gas-optimized, secure, and follows industry best practices. You always consider security implications and write corresponding tests.

### Core Principles

- **Security First**: Always prioritize security over convenience. Follow checks-effects-interactions pattern.
- **Gas Optimization**: Write gas-efficient code without compromising readability or security.
- **Upgradeable Design**: Use proven upgradeability patterns (UUPS) when required.
- **Documentation**: Comprehensive NatSpec documentation for all public interfaces.

### Style Guide Compliance

#### Base Standard

Unless an exception or addition is specifically noted, we follow the [Solidity Style Guide](https://docs.soliditylang.org/en/latest/style-guide.html).

#### Key Exceptions and Additions

##### 1. Internal Library Functions

**Names of internal functions in a library should NOT have an underscore prefix.**

```solidity
// GOOD: Clear and readable
Library.function()

// BAD: Visually confusing
Library._function()
```

##### 2. Error Handling

- **Prefer custom errors** over `require` strings for gas efficiency
- **Custom error names should be CapWords style** (e.g., `InsufficientBalance`, `Unauthorized`)

##### 3. Events

- **Event names should be past tense** - Events track things that _happened_
- Using past tense helps avoid naming collisions with structs or functions
- Example: `TokenTransferred` not `TokenTransfer`

##### 4. Mappings

**Prefer named parameters in mapping types** for clarity:

```solidity
// GOOD
mapping(address account => mapping(address asset => uint256 amount)) public balances;

// BAD
mapping(uint256 => mapping(address => uint256)) public balances;
```

##### 5. Contract Architecture

- **Prefer composition over inheritance** when functions could reasonably be in separate contracts
- **Avoid writing interfaces** unless absolutely necessary - they separate NatSpec from logic
- **Avoid using assembly** unless gas savings are very consequential (>25%)

##### 6. Imports

**Use named imports** and order alphabetically:

```solidity
// GOOD
import {Contract} from "./contract.sol";

// Group imports by external and local
import {Math} from '/solady/Math.sol';

import {MyHelper} from './MyHelper.sol';
```

##### 7. Testing Standards

- **Test file names**: `ContractName.t.sol`
- **Test contract names**: `ContractNameTest` or `FunctionNameTest`
- **Test function names**: If the test contract is already named after the function, omit the funciton name from the test, such as : `test_outcome_optionalContext`, otherwise, if it's not already clear which function is being tested due to the name of the test contract, include the function name in the test name like `test_functionName_outcome_optionalContext` 

**Test Organization Principles:**

**Clear Separation of Concerns**: Core protocol functionality is tested separately from hook-specific behavior to eliminate redundancy and ensure comprehensive coverage.


  ## Test Implementation Rules (implementing pre-written test stubs)
  - Only implement existing test stubs, never create new test functions
  - Only modify specified test files
  - Use inherited test library functions; add utilities to base classes if needed
  - Run `forge fmt` after code changes
  - For revert tests, find typed errors in contract or dependencies

  ## Fuzz Testing
  - Modify fuzz parameters if they don't make sense for the test case
  - Always make sure that any fuzz parameter that is present in a test is actually used.
  - Use `bound()` over `vm.assume()` when possible
  - Define constants instead of magic numbers (e.g., `TOKEN_BALANCE_MAX`)
  - Look at working examples for guidance

  ## Test Quality
  - Run tests after implementation with `-vvvv` for debugging
  - Fix all failures systematically until 100% pass
  - Assert everything necessary to verify expected behavior
  - Handle naming conflicts by adding function name even if the function under test is obvious from the name of the test contract: `test_functionName_scenario`
  - Comment only non-obvious or crucial setup, avoid narration
  - Run full test suite before finishing to ensure no regressions

  ## Bug Reporting
  - If you suspect a protocol bug during testing, stop immediately and report findings with reasoning

### Contract Structure & Organization

#### File Header

```solidity
// SPDX-License-Identifier: Unlicense
pragma solidity 0.8.29;
```

#### Contract Layout (in order)

1. License identifier
2. Pragma statements
3. Import statements
4. Contract declaration
5. State variables (grouped by visibility)
6. Events
7. Errors
8. Modifiers
9. Constructor/Initializer
10. External functions
11. Public functions
12. Internal functions
13. Private functions

### Documentation Standards

#### NatSpec Requirements

- **All external functions, events, and errors should have complete NatSpec**
- Minimally include `@notice`
- Include `@param` and `@return` for parameters and return values

**Example formatting:**

```solidity
/// @notice Brief description
///
/// @dev Implementation details
///
/// @param paramName Parameter description
///
/// @return returnValue Return value description
```

#### Struct Documentation

```solidity
/// @notice A struct describing an account's position
struct Position {
    /// @dev The unix timestamp (seconds) when position was created
    uint256 created;
    /// @dev The amount of ETH in the position
    uint256 amount;
}
```

### Security Standards

#### Input Validation

- Validate all inputs at function entry
- Check for zero addresses where applicable
- Validate array lengths and bounds
- Ensure numeric inputs are within expected ranges

#### State Management

- Update state before external calls
- Use reentrancy guards where needed
- Avoid state changes after external calls

#### Access Control

- Use OpenZeppelin's access control patterns (`OwnableUpgradeable`)
- Create custom modifiers for complex authorization logic
- Always validate caller permissions before state changes

### Gas Optimization Guidelines

#### Storage

- Pack struct members efficiently (256-bit boundaries)
- Use mappings over arrays when possible for lookups
- Minimize storage writes
- Use `immutable` and `constant` appropriately

#### Function Optimization

- Use `external` visibility when function won't be called internally
- Batch operations when possible
- Avoid unbounded loops
- Cache array lengths in memory

### Code Quality Checklist

- [ ] License identifier present
- [ ] Pragma version specified
- [ ] Named imports used and ordered alphabetically
- [ ] NatSpec documentation complete
- [ ] Custom errors defined (CapWords style)
- [ ] Events emitted for state changes (past tense)
- [ ] Input validation implemented
- [ ] Access control enforced
- [ ] Gas optimization considered
- [ ] Security patterns followed
- [ ] Tests written and passing
- [ ] Struct packing optimized
- [ ] Assembly avoided unless >25% gas savings

# important-instruction-reminders

Do what has been asked; nothing more, nothing less.
NEVER create files unless they're absolutely necessary for achieving your goal.
ALWAYS prefer editing an existing file to creating a new one.
NEVER proactively create documentation files (\*.md) or README files. Only create documentation files if explicitly requested by the User.

## Testing Guidelines

- If I am telling you to create tests, and things don't work as expected based on README.md, then always let me know
