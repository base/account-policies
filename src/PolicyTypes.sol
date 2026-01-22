// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @notice Shared types for PolicyManager and policies to avoid circular imports.
library PolicyTypes {
    /// @notice Policy binding parameters authorized by the account.
    struct PolicyBinding {
        address account;
        address policy;
        bytes32 policyConfigHash;
        uint40 validAfter;
        uint40 validUntil;
        uint256 salt;
    }
}

