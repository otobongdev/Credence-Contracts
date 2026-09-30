//! Boundary and recovery coverage for the privileged entry points declared in
//! [`crate::AdminContract`] (`lib.rs`).
//!
//! The assignment requires the five operational state classes — **loading**,
//! **error**, **retry**, **stale**, and **permission** — to behave
//! deterministically *without losing user data*. Every test here therefore
//! asserts three properties at the generated-client transaction boundary:
//!
//! 1. **Stable error** — invalid, out-of-range, stale, paused, or
//!    unauthorised input fails with the documented wire-stable
//!    `credence_errors::ContractError` discriminant.
//! 2. **No data loss** — a rejected call leaves `AdminList`, `RoleAdmins`,
//!    `AdminInfo`, `ConfigEpoch`, and the event stream exactly as they were
//!    (a Soroban panic rolls the whole invocation back, so nothing can be
//!    half-written).
//! 3. **Recovery** — the next legitimate call against fresh state succeeds,
//!    proving the rejection is recoverable rather than terminal.
//!
//! Targeted gaps (previously untested at the client boundary):
//!
//! * uninitialized ("loading") reads and the rejected-then-corrected
//!   `initialize` retry;
//! * the `MaxAdmins` capacity boundary with membership preservation;
//! * the paused gate across *every* privileged mutation in `lib.rs`
//!   (only `add_admin` was covered before);
//! * `get_effective_active_admin_count`, including its inclusive
//!   suspension-expiry and dangling-entry boundaries;
//! * the public `check_role_at_ledger` stale-signature guard (read-only,
//!   no epoch advance, no events).
//!
//! Event assertions follow Soroban testutils semantics: `env.events().all()`
//! reports the events of the **most recent invocation only**, so every event
//! check below is taken immediately after the invocation it describes.

#![cfg(test)]

use crate::*;
use credence_errors::Role;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Env};

// Wire-stable error discriminants (`credence_errors::ContractError`).
// These are asserted through `soroban_sdk::Error::from_contract_error`, the
// same on-wire representation a client observes.
const ERR_NOT_INITIALIZED: u32 = 1;
const ERR_NOT_ADMIN: u32 = 100;
const ERR_CONTRACT_PAUSED: u32 = 106;
const ERR_INVALID_PAUSE_ACTION: u32 = 107;
const ERR_ROLE_NOT_HELD_AT_LEDGER: u32 = 116;
const ERR_THRESHOLD_EXCEEDS_SIGNERS: u32 = 601;

/// Assert that a `try_*` client call failed with the given wire-stable code
/// *and* that the rejected invocation emitted no events (checked immediately,
/// because `events().all()` is scoped to the most recent invocation).
macro_rules! assert_contract_error {
    ($e:expr, $res:expr, $code:expr) => {
        assert_eq!(
            $res.unwrap_err().unwrap(),
            soroban_sdk::Error::from_contract_error($code),
            "rejected call must fail with the documented wire-stable error"
        );
        assert_eq!(
            $e.events().all().len(),
            0,
            "a rejected call must emit no events"
        );
    };
}

/// Assert that the invocation that just ran emitted no event.
///
/// `env.events().all()` is scoped to the frame of the most recent invocation,
/// so this must be called directly after the call under test — an unrelated
/// client call in between would replace that frame and make the check vacuous.
#[track_caller]
fn assert_no_events(e: &Env) {
    assert_eq!(e.events().all().len(), 0, "call must emit no events");
}

/// Register a fresh contract, mock auth for every subsequent invocation, and
/// initialize with the supplied admin-count limits.
fn setup(min_admins: u32, max_admins: u32) -> (Env, AdminContractClient<'static>, Address) {
    let e = Env::default();
    let contract_id = e.register_contract(None, AdminContract);
    let client = AdminContractClient::new(&e, &contract_id);
    let super_admin = Address::generate(&e);
    e.mock_all_auths();
    client.initialize(&super_admin, &min_admins, &max_admins);
    (e, client, super_admin)
}

// ---------------------------------------------------------------------------
// Loading state: uninitialized reads, rejected initialize, corrected retry
// ---------------------------------------------------------------------------

/// Every read against absent storage is defined — a stable error or a
/// documented default — and none of them mutates the epoch or emits events.
/// Rejected `initialize` attempts leave the contract untouched so the
/// corrected retry commits cleanly (recovery, no partially-initialized state).
#[test]
fn uninitialized_reads_are_deterministic_and_initialize_retry_recovers() {
    let e = Env::default();
    let contract_id = e.register_contract(None, AdminContract);
    let client = AdminContractClient::new(&e, &contract_id);
    e.mock_all_auths();
    let stranger = Address::generate(&e);

    // Reads that require configuration or records fail with stable errors …
    assert_contract_error!(e, client.try_get_config(), ERR_NOT_INITIALIZED);
    assert_contract_error!(e, client.try_get_owner(), ERR_NOT_INITIALIZED);
    assert_contract_error!(e, client.try_get_admin_info(&stranger), ERR_NOT_ADMIN);
    assert_contract_error!(e, client.try_get_admin_role(&stranger), ERR_NOT_ADMIN);

    // … while the documented defaults never panic and never mutate state.
    assert_eq!(client.is_admin(&stranger), Role::User);
    assert!(!client.has_role_at_least(&stranger, &AdminRole::Operator));
    let (page, next_cursor) = client.get_all_admins_page(&0u32, &10u32);
    assert_eq!(page.len(), 0);
    assert_eq!(next_cursor, None);
    let (page, next_cursor) = client.get_admins_by_role_page(&AdminRole::SuperAdmin, &0u32, &10u32);
    assert_eq!(page.len(), 0);
    assert_eq!(next_cursor, None);
    // Each read is checked right after it runs, so "reads emit no events" is
    // asserted per read rather than only for the last one.
    assert_eq!(client.get_admin_count(), 0);
    assert_no_events(&e);
    assert_eq!(client.get_active_admin_count(), 0);
    assert_no_events(&e);
    assert_eq!(client.get_effective_active_admin_count(), 0);
    assert_no_events(&e);
    assert_eq!(client.get_config_epoch(), 0);
    assert_no_events(&e);

    // Error state: invalid initializations are rejected before any write …
    assert_contract_error!(
        e,
        client.try_initialize(&stranger, &0u32, &100u32),
        ERR_INVALID_PAUSE_ACTION
    );
    assert_contract_error!(
        e,
        client.try_initialize(&stranger, &10u32, &9u32),
        ERR_INVALID_PAUSE_ACTION
    );

    // … so the contract is still fully uninitialized after both rejections:
    // no `Initialized` flag, no config, no epoch, no admin list.
    assert_contract_error!(e, client.try_get_config(), ERR_NOT_INITIALIZED);
    assert_eq!(client.get_admin_count(), 0);
    assert_eq!(client.get_config_epoch(), 0);
    assert_no_events(&e);

    // Recovery: the corrected retry commits exactly once, with exactly the
    // documented `admin_initialized` event.
    client.initialize(&stranger, &1u32, &100u32);
    assert_eq!(
        e.events().all().len(),
        1,
        "initialize must emit exactly admin_initialized"
    );
    assert_eq!(client.get_config(), (1u32, 100u32));
    assert_eq!(client.get_admin_count(), 1);
    assert_eq!(client.is_admin(&stranger), Role::Admin);
}

// ---------------------------------------------------------------------------
// Error/boundary state: MaxAdmins capacity, membership preservation, recovery
// ---------------------------------------------------------------------------

/// Exactly `MaxAdmins` admins fit; one more is rejected with the stable code
/// and cannot disturb membership, role lists, or the epoch. Freeing a slot
/// makes the identical retry succeed.
#[test]
fn max_admins_capacity_boundary_preserves_membership_and_recovers() {
    let (e, client, super_admin) = setup(1, 2);

    let admin_a = Address::generate(&e);
    client.add_admin(&super_admin, &admin_a, &AdminRole::Admin);
    assert_eq!(
        e.events().all().len(),
        2,
        "a committed add emits admin_added + ROLE_ASSIGNED"
    );
    assert_eq!(client.get_admin_count(), 2); // exactly at the cap
    let epoch_at_cap = client.get_config_epoch();

    // Boundary +1: one admin past the cap is rejected deterministically and
    // emits nothing.
    let admin_b = Address::generate(&e);
    assert_contract_error!(
        e,
        client.try_add_admin(&super_admin, &admin_b, &AdminRole::Admin),
        ERR_THRESHOLD_EXCEEDS_SIGNERS
    );

    // No data loss: membership, role lists, and epoch are untouched.
    assert_eq!(client.get_admin_count(), 2);
    let (list, _) = client.get_all_admins_page(&0u32, &10u32);
    assert_eq!(list.len(), 2);
    assert!(!list.iter().any(|a| a == admin_b));
    let (role_admins, _) = client.get_admins_by_role_page(&AdminRole::Admin, &0u32, &10u32);
    assert_eq!(role_admins.len(), 1);
    assert_eq!(client.get_config_epoch(), epoch_at_cap);

    // Recovery: once a slot frees up, the identical request succeeds.
    client.remove_admin(&super_admin, &admin_a);
    client.add_admin(&super_admin, &admin_b, &AdminRole::Admin);
    assert_eq!(client.get_admin_count(), 2);
    assert_eq!(client.get_config_epoch(), epoch_at_cap + 2);
}

// ---------------------------------------------------------------------------
// Permission state: the paused gate across every privileged mutation
// ---------------------------------------------------------------------------

/// While the contract is paused, every privileged mutation in `lib.rs` is
/// rejected with `ContractPaused` *before* any state is read or written, and
/// the governance data survives untouched. Reads keep working (loading state),
/// a duplicate `pause` stays an idempotent no-op, and `unpause` restores
/// normal operation (recovery).
#[test]
fn paused_gate_rejects_every_privileged_mutation_and_unpause_recovers() {
    let (e, client, super_admin) = setup(1, 100);
    let target = Address::generate(&e);
    client.add_admin(&super_admin, &target, &AdminRole::Admin);

    client.pause(&super_admin);
    assert_eq!(
        e.events().all().len(),
        1,
        "the first direct pause emits exactly the paused event"
    );
    assert!(client.is_paused());
    let paused_epoch = client.get_config_epoch();

    // A duplicated pause is an idempotent no-op: no event, no epoch advance.
    assert_eq!(client.pause(&super_admin), None);
    assert_eq!(
        e.events().all().len(),
        0,
        "a duplicate pause must be a silent no-op"
    );
    assert_eq!(client.get_config_epoch(), paused_epoch);

    // Every privileged mutation is gated, regardless of caller authority or
    // target state (the gate runs before authorization or state validation).
    let stranger = Address::generate(&e);
    assert_contract_error!(
        e,
        client.try_add_admin(&super_admin, &stranger, &AdminRole::Admin),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_remove_admin(&super_admin, &target),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_update_admin_role(&super_admin, &target, &AdminRole::Operator),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_deactivate_admin(&super_admin, &target),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_reactivate_admin(&super_admin, &target),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_suspend_admin(&super_admin, &target, &(e.ledger().timestamp() + 100)),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_transfer_ownership(&super_admin, &target),
        ERR_CONTRACT_PAUSED
    );
    assert_contract_error!(
        e,
        client.try_accept_ownership(&super_admin),
        ERR_CONTRACT_PAUSED
    );

    // Loading state: reads still answer while paused, and none of the
    // rejections moved the epoch or the admin set.
    assert!(client.is_paused());
    assert_eq!(client.get_config(), (1u32, 100u32));
    assert_eq!(client.get_admin_count(), 2);
    assert_eq!(client.is_admin(&target), Role::Admin);
    assert_eq!(client.get_config_epoch(), paused_epoch);

    // Recovery: unpausing restores ordinary operation and the rejected
    // mutation then commits exactly once.
    client.unpause(&super_admin);
    assert!(!client.is_paused());
    client.add_admin(&super_admin, &stranger, &AdminRole::Admin);
    assert_eq!(client.get_admin_count(), 3);
    assert_eq!(client.get_config_epoch(), paused_epoch + 2);
}

// ---------------------------------------------------------------------------
// Stale/timing state: suspension window, inclusive expiry, dangling entries
// ---------------------------------------------------------------------------

/// `get_effective_active_admin_count` must track the suspension window with an
/// inclusive expiry boundary (effective again *at* `suspended_until`, no second
/// transaction, no epoch bump), never lose the suspended admin's record, and
/// skip dangling `AdminList` entries without panicking.
#[test]
fn effective_count_tracks_suspension_with_inclusive_expiry_and_dangling_entry_boundary() {
    let (e, client, super_admin) = setup(1, 100);
    let target = Address::generate(&e);
    client.add_admin(&super_admin, &target, &AdminRole::Admin);
    assert_eq!(client.get_effective_active_admin_count(), 2);

    let until = e.ledger().timestamp() + 100;
    client.suspend_admin(&super_admin, &target, &until);
    let epoch_after_suspend = client.get_config_epoch();

    // While suspended: excluded from the effective count, but the record —
    // role, active flag, suspension window — is fully preserved.
    assert_eq!(client.get_effective_active_admin_count(), 1);
    assert_eq!(client.is_admin(&target), Role::User);
    assert!(!client.has_role_at_least(&target, &AdminRole::Admin));
    let info = client.get_admin_info(&target);
    assert_eq!(info.role, AdminRole::Admin);
    assert!(info.active);
    assert_eq!(info.suspended_until, until);

    // One second before expiry: still suspended.
    e.ledger().with_mut(|ledger| ledger.timestamp = until - 1);
    assert_eq!(client.get_effective_active_admin_count(), 1);
    assert_eq!(client.is_admin(&target), Role::User);

    // Exact boundary: at `suspended_until` the admin is effective again with
    // no second transaction and no epoch advance (inclusive `>=` comparison).
    e.ledger().with_mut(|ledger| ledger.timestamp = until);
    assert_eq!(client.get_effective_active_admin_count(), 2);
    assert_eq!(client.is_admin(&target), Role::Admin);
    assert!(client.has_role_at_least(&target, &AdminRole::Admin));
    assert_eq!(client.get_config_epoch(), epoch_after_suspend);

    // Dangling-entry boundary: an `AdminList` entry without an `AdminInfo`
    // record is skipped by the effective count and never panics, while the
    // raw list length still reports it.
    let dangling = Address::generate(&e);
    e.as_contract(&client.address, || {
        let mut list: soroban_sdk::Vec<Address> = e
            .storage()
            .instance()
            .get(&DataKey::AdminList)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&e));
        list.push_back(dangling);
        e.storage().instance().set(&DataKey::AdminList, &list);
    });
    assert_eq!(client.get_effective_active_admin_count(), 2);
    assert_eq!(client.get_admin_count(), 3);
}

// ---------------------------------------------------------------------------
// Permission state: deactivation preserves the record, reactivation recovers
// ---------------------------------------------------------------------------

/// Deactivation removes *authority* only: the `AdminInfo` record (role,
/// assignment history) is untouched apart from the `active` flag, both count
/// entry points drop, and `reactivate_admin` restores everything exactly.
#[test]
fn deactivation_preserves_record_and_reactivation_restores_counts() {
    let (e, client, super_admin) = setup(1, 100);
    let target = Address::generate(&e);
    client.add_admin(&super_admin, &target, &AdminRole::Admin);

    let before = client.get_admin_info(&target);
    let epoch_before_deactivate = client.get_config_epoch();

    client.deactivate_admin(&super_admin, &target);
    assert_eq!(
        client.get_config_epoch(),
        epoch_before_deactivate + 1,
        "a committed deactivation advances the epoch exactly once"
    );
    assert_eq!(client.get_effective_active_admin_count(), 1);
    assert_eq!(client.get_active_admin_count(), 1);
    assert_eq!(client.is_admin(&target), Role::User);
    assert!(!client.has_role_at_least(&target, &AdminRole::Admin));

    // No user data lost: only `active` changed.
    let during = client.get_admin_info(&target);
    assert_eq!(during.role, before.role);
    assert_eq!(during.assigned_at, before.assigned_at);
    assert_eq!(during.assigned_by, before.assigned_by);
    assert_eq!(during.suspended_until, before.suspended_until);
    assert!(!during.active);

    // Recovery: reactivation restores authority and both counters exactly.
    client.reactivate_admin(&super_admin, &target);
    assert_eq!(client.get_config_epoch(), epoch_before_deactivate + 2);
    assert_eq!(client.get_effective_active_admin_count(), 2);
    assert_eq!(client.get_active_admin_count(), 2);
    assert_eq!(client.is_admin(&target), Role::Admin);
    assert!(client.has_role_at_least(&target, &AdminRole::Admin));
    let after = client.get_admin_info(&target);
    assert_eq!(after.role, before.role);
    assert_eq!(after.assigned_at, before.assigned_at);
    assert_eq!(after.assigned_by, before.assigned_by);
    assert!(after.active);
}

// ---------------------------------------------------------------------------
// Stale state: historical role checks are read-only and block replays
// ---------------------------------------------------------------------------

/// `check_role_at_ledger` is the replay guard for off-chain signed actions:
/// it must accept a signature produced at (or after) the grant timestamp,
/// reject anything that predates it with `RoleNotHeldAtLedger`, reject
/// unknown or under-ranked actors with `NotAdmin` — and never advance the
/// epoch or emit an event in either direction.
#[test]
fn historical_role_check_is_read_only_and_rejects_stale_signatures() {
    let e = Env::default();
    let contract_id = e.register_contract(None, AdminContract);
    let client = AdminContractClient::new(&e, &contract_id);
    e.mock_all_auths();

    // Fix a real ledger time so `assigned_at` boundaries are meaningful.
    let t0: u64 = 1_000;
    e.ledger().with_mut(|ledger| ledger.timestamp = t0);
    let super_admin = Address::generate(&e);
    client.initialize(&super_admin, &1u32, &100u32);
    let operator = Address::generate(&e);
    client.add_admin(&super_admin, &operator, &AdminRole::Operator);

    // A second admin is granted later, at `t1` — the replay window under test.
    let t1: u64 = t0 + 500;
    e.ledger().with_mut(|ledger| ledger.timestamp = t1);
    let late_admin = Address::generate(&e);
    client.add_admin(&super_admin, &late_admin, &AdminRole::Admin);
    let stranger = Address::generate(&e);

    // All setup mutations are done; from here on the epoch must not move.
    let epoch_before_checks = client.get_config_epoch();

    // Exact boundary: a signature produced at the assignment timestamp passes.
    client.check_role_at_ledger(&AdminRole::SuperAdmin, &super_admin, &t0);
    assert_no_events(&e);

    // One second before the grant: stale — the signer was not yet authorised.
    assert_contract_error!(
        e,
        client.try_check_role_at_ledger(&AdminRole::SuperAdmin, &super_admin, &(t0 - 1)),
        ERR_ROLE_NOT_HELD_AT_LEDGER
    );

    // Unknown actor and under-ranked actor: stable NotAdmin.
    assert_contract_error!(
        e,
        client.try_check_role_at_ledger(&AdminRole::SuperAdmin, &stranger, &t0),
        ERR_NOT_ADMIN
    );
    assert_contract_error!(
        e,
        client.try_check_role_at_ledger(&AdminRole::SuperAdmin, &operator, &t0),
        ERR_NOT_ADMIN
    );

    // Replay window: an admin granted at `t1` cannot legitimise a signature
    // that claims authority at an earlier ledger.
    client.check_role_at_ledger(&AdminRole::Admin, &late_admin, &t1);
    assert_no_events(&e);
    assert_contract_error!(
        e,
        client.try_check_role_at_ledger(&AdminRole::Admin, &late_admin, &(t1 - 1)),
        ERR_ROLE_NOT_HELD_AT_LEDGER
    );

    // Read-only invariant: passing *and* failing checks advance no epoch, so
    // observers can never see a phantom mutation.
    assert_eq!(client.get_config_epoch(), epoch_before_checks);
}
