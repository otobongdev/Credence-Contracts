//! Interface for flashloan receivers.
//! Contracts that wish to receive flashloans from the Credence Treasury must implement this trait.

use soroban_sdk::{contractclient, Address, Bytes, Env, Symbol};

/// @notice Defines the magic value returned on successful flashloan execution.
pub const FLASH_LOAN_SUCCESS: &str = "FLASH_LOAN_SUCCESS";

/// @title  FlashLoanReceiver
/// @notice Interface for a flashloan receiver contract.
#[contractclient(name = "FlashLoanReceiverClient")]
pub trait FlashLoanReceiver {
    /// @notice Callback invoked by the treasury after transferring the loan amount.
    /// @param  initiator The address that initiated the flashloan.
    /// @param  token     The address of the token being loaned.
    /// @param  amount    The amount of tokens loaned.
    /// @param  fee       The fee amount required to be repaid along with the principal.
    /// @param  data      Arbitrary data passed by the initiator.
    /// @return A symbol that must match `FLASH_LOAN_SUCCESS` for the loan to be considered successful.
    fn on_flash_loan(
        e: Env,
        initiator: Address,
        token: Address,
        amount: i128,
        fee: i128,
        data: Bytes,
    ) -> Symbol;
}
