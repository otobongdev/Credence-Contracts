#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

mod error;
pub use error::DisputeError;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisputeStatus {
    Open,
    Resolved,
    Closed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dispute {
    pub id: u64,
    pub status: DisputeStatus,
    pub resolver: Address,
}

#[contract]
pub struct DisputeResolutionContract;

#[contractimpl]
impl DisputeResolutionContract {
    pub fn create_dispute(env: Env, resolver: Address) -> u64 {
        // Deterministic within a transaction: the host PRNG is seeded per
        // invocation, so replaying the same transaction yields the same id.
        let id = env.prng().gen::<u64>();
        let dispute = Dispute {
            id,
            status: DisputeStatus::Open,
            resolver,
        };
        env.storage().instance().set(&id, &dispute);
        id
    }

    pub fn get_dispute(env: Env, id: u64) -> Result<Dispute, DisputeError> {
        env.storage()
            .instance()
            .get(&id)
            .ok_or(DisputeError::DisputeNotFound)
    }

    /// Close a dispute.
    ///
    /// The caller is passed explicitly and must authenticate itself: Soroban
    /// exposes no "invoker address" to contract code, so passing the address
    /// and calling `require_auth` is the only way to bind the close to a real
    /// party.
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), DisputeError> {
        caller.require_auth();

        let mut dispute = Self::get_dispute(env.clone(), id)?;

        // Invariant 1: No double-close
        if dispute.status == DisputeStatus::Closed {
            return Err(DisputeError::AlreadyClosed);
        }

        // Invariant 2: No unauthorized close
        if caller != dispute.resolver {
            return Err(DisputeError::Unauthorized);
        }

        // Update to terminal state
        dispute.status = DisputeStatus::Closed;
        env.storage().instance().set(&id, &dispute);

        // Emit event
        env.events()
            .publish((symbol_short!("closed"), id), (symbol_short!("by"), caller));

        Ok(())
    }
}
