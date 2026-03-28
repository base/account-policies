// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

/// @title PublicERC6492Validator
///
/// @notice Validate ERC-6492 signatures and perform contract deployment or preparation when necessary
///         (https://eips.ethereum.org/EIPS/eip-6492).
///
/// @dev Anyone can make arbitrary calls from this contract, so it should never have privileged access control.
///
/// @author Coinbase (https://github.com/base/account-policies)
contract PublicERC6492Validator {
    /// @notice Solady's pre-deployed non-reverting ERC-6492 verifier, required for counterfactual signature validation.
    address internal constant _ERC6492_VERIFIER = 0x0000bc370E4DC924F427d84e2f4B9Ec81626ba7E;

    /// @notice Thrown when the Solady ERC-6492 verifier contract is not deployed on this chain.
    error ERC6492VerifierNotDeployed();

    constructor() {
        if (_ERC6492_VERIFIER.code.length == 0) revert ERC6492VerifierNotDeployed();
    }

    /// @notice Validate contract signature and execute side effects if provided.
    ///
    /// @dev If the signature is postfixed with the ERC-6492 magic value, an external call to deploy/prepare the account
    ///      is made before calling ERC-1271 `isValidSignature`.
    ///
    /// @dev This function is NOT reentrancy safe.
    ///
    /// @param account Account being validated (EOA or smart contract wallet).
    /// @param hash Signed digest.
    /// @param signature ERC-6492 signature bytes.
    ///
    /// @return isValid True if signature is valid.
    function isValidSignatureNowAllowSideEffects(address account, bytes32 hash, bytes calldata signature)
        external
        returns (bool)
    {
        return SignatureCheckerLib.isValidERC6492SignatureNowAllowSideEffects(account, hash, signature);
    }
}
