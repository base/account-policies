// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IMorphoVault} from "./interfaces/morpho/IMorphoVault.sol";
import {ISwapRouter} from "./interfaces/uniswap/ISwapRouter.sol";

/// @title AutoCompoundPeriphery
///
/// @notice Stateless periphery that atomically swaps MORPHO → USDC and deposits into a Morpho vault in a single call.
///
/// @dev This contract exists because the account-policies framework builds the full call plan before any calls
///      execute — the policy can't observe the swap output to size the deposit dynamically. By collapsing swap +
///      deposit into one call frame, this contract can read the actual swap output and deposit the exact amount.
///
///      Trust model: callable by anyone. The guard is the token approval — callers must approve MORPHO to this
///      contract before calling `swapAndDeposit`. The contract consumes the full approved amount in a single call
///      and ends every transaction holding zero tokens.
///
///      Non-upgradeable by design. Deployed once per DEX interface.
contract AutoCompoundPeriphery {
    ////////////////////////////////////////////////////////////////
    ///                    Constants/Storage                     ///
    ////////////////////////////////////////////////////////////////

    /// @notice Uniswap V3 swap router.
    address public immutable SWAP_ROUTER;

    /// @notice MORPHO token address.
    address public immutable MORPHO_TOKEN;

    /// @notice USDC token address.
    address public immutable USDC;

    ////////////////////////////////////////////////////////////////
    ///                         Errors                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Thrown when the swap router address has no deployed code.
    error SwapRouterNotContract(address swapRouter);

    /// @notice Thrown when the MORPHO token address has no deployed code.
    error MorphoTokenNotContract(address morphoToken);

    /// @notice Thrown when the USDC token address has no deployed code.
    error UsdcNotContract(address usdc);

    /// @notice Thrown when the vault address has no deployed code.
    error VaultNotContract(address vault);

    /// @notice Thrown when the MORPHO amount is zero.
    error ZeroAmount();

    /// @notice Thrown when the recipient is the zero address.
    error ZeroRecipient();

    ////////////////////////////////////////////////////////////////
    ///                         Events                           ///
    ////////////////////////////////////////////////////////////////

    /// @notice Emitted after a successful swap-and-deposit.
    ///
    /// @param caller Address that initiated the call (typically the user's smart wallet).
    /// @param recipient Address that received the vault shares.
    /// @param vault Morpho vault that received the USDC deposit.
    /// @param morphoSwapped Amount of MORPHO swapped.
    /// @param usdcReceived Amount of USDC received from the swap.
    /// @param sharesReceived Amount of vault shares minted to the recipient.
    event SwappedAndDeposited(
        address indexed caller,
        address indexed recipient,
        address indexed vault,
        uint256 morphoSwapped,
        uint256 usdcReceived,
        uint256 sharesReceived
    );

    ////////////////////////////////////////////////////////////////
    ///                       Constructor                        ///
    ////////////////////////////////////////////////////////////////

    /// @notice Deploys the periphery with immutable token and router addresses.
    ///
    /// @param swapRouter_ Uniswap V3 swap router address.
    /// @param morphoToken_ MORPHO token address.
    /// @param usdc_ USDC token address.
    constructor(address swapRouter_, address morphoToken_, address usdc_) {
        if (swapRouter_.code.length == 0) revert SwapRouterNotContract(swapRouter_);
        if (morphoToken_.code.length == 0) revert MorphoTokenNotContract(morphoToken_);
        if (usdc_.code.length == 0) revert UsdcNotContract(usdc_);

        SWAP_ROUTER = swapRouter_;
        MORPHO_TOKEN = morphoToken_;
        USDC = usdc_;
    }

    ////////////////////////////////////////////////////////////////
    ///                    External Functions                    ///
    ////////////////////////////////////////////////////////////////

    /// @notice Pulls MORPHO from the caller, swaps to USDC, and deposits into a Morpho vault.
    ///
    /// @dev The caller must have approved this contract to spend `morphoAmount` of MORPHO before calling.
    ///      The vault shares are minted to `recipient` (typically the user's smart wallet).
    ///      This contract holds zero tokens after the call completes.
    ///
    /// @param vault Morpho vault to deposit into.
    /// @param morphoAmount Amount of MORPHO to swap.
    /// @param minAmountOut Minimum USDC to accept from the swap (sandwich protection).
    /// @param poolFee Uniswap V3 pool fee tier for the MORPHO/USDC pair.
    /// @param recipient Address that receives the minted vault shares.
    ///
    /// @return usdcDeposited Amount of USDC deposited into the vault.
    /// @return sharesReceived Amount of vault shares minted to the recipient.
    function swapAndDeposit(
        address vault,
        uint256 morphoAmount,
        uint256 minAmountOut,
        uint24 poolFee,
        address recipient
    ) external returns (uint256 usdcDeposited, uint256 sharesReceived) {
        if (morphoAmount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroRecipient();
        if (vault.code.length == 0) revert VaultNotContract(vault);

        // Pull MORPHO from caller (the smart wallet).
        IERC20(MORPHO_TOKEN).transferFrom(msg.sender, address(this), morphoAmount);

        // Approve router and swap MORPHO → USDC.
        IERC20(MORPHO_TOKEN).approve(SWAP_ROUTER, morphoAmount);
        uint256 usdcReceived = ISwapRouter(SWAP_ROUTER)
            .exactInputSingle(
                ISwapRouter.ExactInputSingleParams({
                    tokenIn: MORPHO_TOKEN,
                    tokenOut: USDC,
                    fee: poolFee,
                    recipient: address(this),
                    amountIn: morphoAmount,
                    amountOutMinimum: minAmountOut,
                    sqrtPriceLimitX96: 0
                })
            );

        // Deposit all received USDC into the vault, minting shares to the recipient.
        IERC20(USDC).approve(vault, usdcReceived);
        sharesReceived = IMorphoVault(vault).deposit(usdcReceived, recipient);
        usdcDeposited = usdcReceived;

        emit SwappedAndDeposited(msg.sender, recipient, vault, morphoAmount, usdcReceived, sharesReceived);
    }
}
