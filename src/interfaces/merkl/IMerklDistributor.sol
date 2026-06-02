// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title IMerklDistributor
///
/// @notice Minimal interface for the Merkl rewards distributor used by auto-compound policies.
///
/// @dev Amounts in the merkle tree are cumulative. The distributor tracks `claimed[user][token]` internally and
///      pays out the delta on each call. The caller (`msg.sender`) must either be the `user` or an authorized
///      operator.
interface IMerklDistributor {
    /// @notice Claims accrued rewards for one or more (user, token) pairs.
    ///
    /// @param users Addresses to claim for (must be msg.sender or msg.sender must be an authorized operator).
    /// @param tokens Reward token addresses.
    /// @param amounts Cumulative claimable amounts (not incremental).
    /// @param proofs Merkle proofs validating each (user, token, amount) leaf.
    function claim(
        address[] calldata users,
        address[] calldata tokens,
        uint256[] calldata amounts,
        bytes32[][] calldata proofs
    ) external;
}
