// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/// @title ISwapRouter
///
/// @notice Minimal Uniswap V3 SwapRouter interface for single-hop exact-input swaps.
///
/// @dev Based on the Uniswap V3 SwapRouter02 interface (no deadline in params).
interface ISwapRouter {
    /// @notice Parameters for a single-hop exact-input swap.
    struct ExactInputSingleParams {
        /// @dev Token to swap from.
        address tokenIn;
        /// @dev Token to swap to.
        address tokenOut;
        /// @dev Uniswap V3 pool fee tier (e.g., 500, 3000, 10000).
        uint24 fee;
        /// @dev Address that receives the output tokens.
        address recipient;
        /// @dev Exact amount of `tokenIn` to swap.
        uint256 amountIn;
        /// @dev Minimum acceptable amount of `tokenOut` (sandwich protection).
        uint256 amountOutMinimum;
        /// @dev Price limit for the swap (0 = no limit).
        uint160 sqrtPriceLimitX96;
    }

    /// @notice Executes a single-hop exact-input swap.
    ///
    /// @param params Swap parameters.
    ///
    /// @return amountOut Amount of `tokenOut` received.
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);
}
