use soroban_sdk::{contractclient, Address, Env};

/// Governable defines the minimal administrative control interface
/// for a contract.
///
/// # Invariants
///
/// - There is always exactly one admin address at any time.
/// - `set_admin` must be authorized by the current admin.
/// - A successful `set_admin` fully replaces the previous admin; the
///   previous admin loses all administrative privileges immediately.
/// - The admin address must never be the zero/default address.
///
/// # Failure modes
///
/// - Authorization failure: a caller that is not the current admin must
///   cause `set_admin` to revert with an authorization error.
/// - Invalid input: attempting to transfer to the zero address must revert
///   without mutating state.
/// - Self-transfer: transferring to the current admin is a no-op and must
///   not corrupt state.
///
/// # Observability
///
/// Implementations should emit a event on admin transfer so that operators
/// can diagnose failures without exposing sensitive data. The event must not
/// contain anything other than the new admin address.
#[contractclient(name = "GovernableClient")]
pub trait Governable {
    /// Get the current admin address.
    ///
    /// Returns the admin that is currently authorized to call `set_admin`.
    /// This function is always safe to call and never mutates state.
    fn get_admin(env: Env) -> Address;

    /// Transfer administrative control to a new address.
    ///
    /// # Authorization
    ///
    /// Requires authorization from the current admin. Callers that are not
    /// the current admin must be rejected.
    ///
    /// # Validation
    ///
    /// `new_admin` must not be the zero address. Transferring to the
    /// current admin is a no-op and must not corrupt state.
    ///
    /// # State transition
    ///
    /// On success, the previous admin is replaced atomically; there is no
    /// intermediate state in which neither address holds administrative
    /// control. If the call reverts, administrative control remains with
    /// the original admin.
    fn set_admin(env: Env, new_admin: Address);
}

/// Test module covering boundary and recovery scenarios for the
/// `Governable` interface.
///
/// These tests exercise the interface through a minimal in-memory
/// implementation that enforces the documented invariants. They validate:
///
/// - successful admin transfer,
/// - rejection of unauthorized callers,
/// - boundary behavior for self-transfer,
/// - recovery after a failed transfer (state must be unchanged),
/// - determinism across repeated calls.
#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::contract;
    use soroban_sdk::contractimpl;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::testutils::Events;
    use soroban_sdk::Symbol;

    /// Storage key holding the single admin address.
    const ADMIN_KEY: &str = "admin";

    /// Stable rejection reason for a caller that is not the current admin.
    const ERR_UNAUTHORIZED: &str = "unauthorized";

    /// Minimal reference implementation of the `Governable` interface,
    /// used to drive the interface tests. This is not shipped in
    /// production code; it exists only to validate the contract that
    /// consumers of the interface must uphold.
    #[contract]
    pub struct ReferenceGovernable;

    impl ReferenceGovernable {
        /// Seeds the admin. Test-only setup, never part of the interface.
        fn init(env: &Env, admin: &Address) {
            env.storage().persistent().set(&ADMIN_KEY, admin);
        }

        /// Read the admin, or `None` while the contract is uninitialized.
        ///
        /// Split out from [`Governable::get_admin`] so a test can observe
        /// the *loading* state directly, without provoking a panic.
        fn read_admin(env: &Env) -> Option<Address> {
            env.storage().persistent().get(&ADMIN_KEY)
        }

        /// The fallible core of a transfer, so a test can assert both the
        /// rejection **and** that the rejected call mutated nothing.
        ///
        /// Every check runs before any write, so a returned `Err` means the
        /// previous admin is still in force: that is the recovery guarantee
        /// the interface documents for a reverted call.
        fn try_set_admin(
            env: &Env,
            caller: &Address,
            new_admin: &Address,
        ) -> Result<(), &'static str> {
            // Authorization: only the current admin may transfer control.
            if Some(caller) != Self::read_admin(env).as_ref() {
                return Err(ERR_UNAUTHORIZED);
            }
            // Boundary: self-transfer is a documented no-op. Returning early
            // keeps it from rewriting storage or emitting a transfer event.
            if new_admin == caller {
                return Ok(());
            }
            // Atomic replacement: one write, no intermediate state.
            env.storage().persistent().set(&ADMIN_KEY, new_admin);
            // Observability: the event carries only the new admin address.
            env.events()
                .publish((Symbol::new(env, "admin_transferred"),), new_admin);
            Ok(())
        }
    }

    #[contractimpl]
    impl Governable for ReferenceGovernable {
        fn get_admin(env: Env) -> Address {
            Self::read_admin(&env).expect("admin not initialized")
        }

        fn set_admin(env: Env, new_admin: Address) {
            // Authorization is demanded first, before any state is written, so
            // an unauthenticated caller can neither transfer control nor use
            // the error to probe whether the contract is initialized.
            let current = Self::read_admin(&env).expect("admin not initialized");
            current.require_auth();
            // `require_auth` proved the caller authorized the current admin,
            // so the write below is the authorized path.
            Self::try_set_admin(&env, &current, &new_admin)
                .expect("Governable::set_admin rejected the transfer");
        }
    }

    /// Deploy the mock and register `admin` as its single admin.
    /// Returns `(env, contract_id, admin, other)`.
    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register(ReferenceGovernable, ());
        let admin = Address::generate(&env);
        let other = Address::generate(&env);
        env.as_contract(&contract_id, || {
            ReferenceGovernable::init(&env, &admin);
        });
        (env, contract_id, admin, other)
    }

    // --- Success: the current admin can transfer control ---

    #[test]
    fn get_admin_returns_the_registered_admin() {
        let (env, contract_id, admin, _) = setup();
        let observed =
            env.as_contract(&contract_id, || ReferenceGovernable::get_admin(env.clone()));
        assert_eq!(observed, admin);
    }

    #[test]
    fn set_admin_transfers_control_to_the_new_admin() {
        let (env, contract_id, _, _) = setup();
        let new_admin = Address::generate(&env);
        env.mock_all_auths();
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        client.set_admin(&new_admin);

        // A successful transfer is observable for operators. Checked
        // immediately: `events().all()` is scoped to the most recent
        // invocation, and the read below would replace that frame.
        assert_eq!(env.events().all().len(), 1);

        // Atomic replacement: the new admin is in force immediately, so there
        // is no state in which neither address holds control.
        assert_eq!(client.get_admin(), new_admin);
    }

    // --- Rejection: uninitialized state and missing authorization ---

    #[test]
    fn get_admin_is_rejected_while_uninitialized() {
        let env = Env::default();
        let contract_id = env.register(ReferenceGovernable, ());
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        // Loading state: a read with no stored admin fails deterministically
        // instead of returning a bogus address.
        assert!(client.try_get_admin().is_err());
    }

    #[test]
    fn set_admin_is_rejected_without_authorization() {
        let (env, contract_id, admin, _) = setup();
        let new_admin = Address::generate(&env);
        // No auth is mocked: nobody has authorized the current admin.
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        assert!(client.try_set_admin(&new_admin).is_err());

        // No data loss: the admin is untouched by the rejected call.
        assert_eq!(client.get_admin(), admin);
        assert_eq!(env.events().all().len(), 0);
    }

    #[test]
    fn unauthorized_transfer_reports_an_error_and_preserves_the_admin() {
        let (env, contract_id, admin, other) = setup();
        let new_admin = Address::generate(&env);
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        let rejected = env.as_contract(&contract_id, || {
            ReferenceGovernable::try_set_admin(&env, &other, &new_admin)
        });
        assert_eq!(rejected, Err(ERR_UNAUTHORIZED));
        assert_eq!(client.get_admin(), admin);
        // The rejected call is the most recent invocation: it emitted nothing.
        assert_eq!(env.events().all().len(), 0);

        // Recovery: the corrected retry by the real admin commits, exactly
        // once, and only now is a transfer observable.
        let retried = env.as_contract(&contract_id, || {
            ReferenceGovernable::try_set_admin(&env, &admin, &new_admin)
        });
        assert_eq!(retried, Ok(()));
        assert_eq!(env.events().all().len(), 1);
        assert_eq!(client.get_admin(), new_admin);
    }

    // --- Boundary: self-transfer is an idempotent no-op ---

    #[test]
    fn set_admin_self_transfer_is_a_no_op() {
        let (env, contract_id, admin, _) = setup();
        env.mock_all_auths();
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        client.set_admin(&admin);

        // A no-op must not fabricate a transfer event.
        assert_eq!(env.events().all().len(), 0);
        assert_eq!(client.get_admin(), admin);
    }

    // --- Recovery: the previous admin loses control immediately ---

    #[test]
    fn previous_admin_loses_control_after_a_transfer() {
        let (env, contract_id, admin, _) = setup();
        let new_admin = Address::generate(&env);
        env.mock_all_auths();
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        client.set_admin(&new_admin);

        let target = Address::generate(&env);
        // The old admin can no longer transfer, even though it authorized the
        // frame: the admin it authorized has moved on.
        let rejected = env.as_contract(&contract_id, || {
            ReferenceGovernable::try_set_admin(&env, &admin, &target)
        });
        assert_eq!(rejected, Err(ERR_UNAUTHORIZED));
        assert_eq!(client.get_admin(), new_admin);
    }

    // --- Regression: determinism and interface stability ---

    #[test]
    fn get_admin_is_deterministic_and_side_effect_free() {
        let (env, contract_id, admin, _) = setup();
        let client = ReferenceGovernableClient::new(&env, &contract_id);

        for _ in 0..8 {
            assert_eq!(client.get_admin(), admin);
        }
        // Repeated reads emit nothing and leave the admin untouched.
        assert_eq!(env.events().all().len(), 0);
    }

    #[test]
    fn governable_client_is_available() {
        // `#[contractclient]` on the trait keeps a caller-facing client type,
        // so consumers can invoke `Governable` without a hand-written adapter.
        let _client = core::marker::PhantomData::<GovernableClient<'static>>;
    }
}
