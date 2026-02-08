// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {CoinbaseSmartWallet} from "smart-wallet/CoinbaseSmartWallet.sol";

/// @title MockCoinbaseSmartWallet
///
/// @notice Minimal `CoinbaseSmartWallet` test mock used by this repo's tests.
///
/// @dev Forked from the official smart-wallet test mock:
///      `https://github.com/coinbase/smart-wallet/blob/main/test/mocks/MockCoinbaseSmartWallet.sol`.
///      WARNING: testing-only code. Do not copy into production.
contract MockCoinbaseSmartWallet is CoinbaseSmartWallet {
    /// @notice Constructs the mock with relaxed owner indexing for tests.
    constructor() {
        _getMultiOwnableStorage().nextOwnerIndex = 0;
    }

    /// @notice Wraps a raw owner signature in the wallet's signature wrapper encoding.
    ///
    /// @param ownerIndex Owner index used by the wallet.
    /// @param signature Raw signature bytes.
    ///
    /// @return wrappedSignature ABI-encoded `SignatureWrapper`.
    function wrapSignature(uint256 ownerIndex, bytes memory signature)
        public
        pure
        returns (bytes memory wrappedSignature)
    {
        return abi.encode(CoinbaseSmartWallet.SignatureWrapper(ownerIndex, signature));
    }
}

