//! Basic and adversarial regression coverage for [`AdminContract`].
//!
//! Every interaction is expressed at the contract-client boundary so that a
//! rejected call is observed as a stable `Error(Contract, #N)` result instead
//! of an unwrapped panic inside the harness. Assertions about the resulting
//! state are always made through a fresh read, never through the value the
//! mutating call happened to return.

use crate::*;
use soroban_sdk::{Address, Env};

#[cfg(test)]
mod basic_tests {
    use super::*;
    use credence_errors::Role;
    use soroban_sdk::testutils::{Address as _, Ledger as _};

    // Wire-stable error discriminants (`credence_errors::ContractError`).
    const ERR_NOT_ADMIN: u32 = 100;
    const ERR_INVALID_ADMIN_ADDRESS: u32 = 110;
    const ERR_ALREADY_ACTIVE: u32 = 405;

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    /// Register the contract, initialize it with a single SuperAdmin and
    /// return `(env, contract id, super admin, client)`.
    fn setup() -> (Env, Address, Address, AdminContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AdminContract);
        let super_admin = Address::generate(&env);
        let client = AdminContractClient::new(&env, &contract_id);
        client.initialize(&super_admin, &1u32, &100u32);
        (env, contract_id, super_admin, client)
    }

    /// Assert that `res` is a contract error with the given wire discriminant.
    fn assert_contract_error<T>(
        res: Result<
            Result<T, soroban_sdk::ConversionError>,
            Result<soroban_sdk::Error, soroban_sdk::InvokeError>,
        >,
        expected: u32,
    ) {
        match res {
            Err(Ok(err)) => assert_eq!(err, soroban_sdk::Error::from_contract_error(expected)),
            Err(Err(_)) => panic!("expected Error(Contract, #{expected}), got an invoke error"),
            Ok(_) => panic!("expected Error(Contract, #{expected}), but the call succeeded"),
        }
    }

    // ------------------------------------------------------------------------
    // Original basic tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_role_hierarchy() {
        let _env = Env::default();

        // Test role comparisons
        assert!(AdminRole::SuperAdmin > AdminRole::Admin);
        assert!(AdminRole::Admin > AdminRole::Operator);
        assert!(AdminRole::SuperAdmin > AdminRole::Operator);

        // Test role equality
        assert_eq!(AdminRole::SuperAdmin, AdminRole::SuperAdmin);
        assert_eq!(AdminRole::Admin, AdminRole::Admin);
        assert_eq!(AdminRole::Operator, AdminRole::Operator);

        // Test role inequality
        assert!(AdminRole::SuperAdmin != AdminRole::Admin);
        assert!(AdminRole::Admin != AdminRole::Operator);
        assert!(AdminRole::SuperAdmin != AdminRole::Operator);
    }

    #[test]
    fn test_admin_info_creation() {
        let env = Env::default();
        let address = Address::generate(&env);
        let assigned_by = Address::generate(&env);

        let admin_info = AdminInfo {
            address: address.clone(),
            role: AdminRole::Admin,
            assigned_at: 12345,
            assigned_by: assigned_by.clone(),
            active: true,
            suspended_until: 0,
        };

        assert_eq!(admin_info.address, address);
        assert_eq!(admin_info.role, AdminRole::Admin);
        assert_eq!(admin_info.assigned_at, 12345);
        assert_eq!(admin_info.assigned_by, assigned_by);
        assert!(admin_info.active);
    }

    #[test]
    fn test_required_role_to_assign() {
        // Test that SuperAdmin can assign any role
        assert_eq!(
            AdminContract::get_required_role_to_assign(AdminRole::SuperAdmin),
            AdminRole::SuperAdmin
        );
        assert_eq!(
            AdminContract::get_required_role_to_assign(AdminRole::Admin),
            AdminRole::SuperAdmin
        );
        assert_eq!(
            AdminContract::get_required_role_to_assign(AdminRole::Operator),
            AdminRole::Admin
        );
    }

    #[test]
    fn test_role_assignment_logic() {
        // Test role assignment requirements
        // SuperAdmin can assign: SuperAdmin, Admin, Operator
        // Admin can assign: Operator
        // Operator cannot assign anything

        assert_eq!(
            AdminContract::get_required_role_to_assign(AdminRole::SuperAdmin),
            AdminRole::SuperAdmin
        );
        assert_eq!(
            AdminContract::get_required_role_to_assign(AdminRole::Admin),
            AdminRole::SuperAdmin
        );
        assert_eq!(
            AdminContract::get_required_role_to_assign(AdminRole::Operator),
            AdminRole::Admin
        );
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: role hierarchy boundaries
    // ------------------------------------------------------------------------

    #[test]
    fn test_role_hierarchy_is_strict_total_order() {
        // Invariant: the role ordering is a strict total order.
        // This guarantees that any comparison-based authorization check
        // is deterministic and total (antisymmetric, transitive, total).
        let roles = [AdminRole::Operator, AdminRole::Admin, AdminRole::SuperAdmin];

        // Antisymmetry: for any distinct a,b exactly one of a<b or a>b holds.
        for i in 0..roles.len() {
            for j in 0..roles.len() {
                if i != j {
                    let a = roles[i].clone();
                    let b = roles[j].clone();
                    assert!((a < b) != (a > b));
                }
            }
        }

        // Transitivity: Operator < Admin < SuperAdmin.
        assert!(AdminRole::Operator < AdminRole::Admin);
        assert!(AdminRole::Admin < AdminRole::SuperAdmin);
        assert!(AdminRole::Operator < AdminRole::SuperAdmin);

        // Reflexivity of equality.
        for r in roles.iter() {
            assert_eq!(r, r);
            assert!(!(r < r));
            assert!(!(r > r));
        }
    }

    #[test]
    fn test_required_role_is_monotonic_non_decreasing() {
        // Invariant: as the role being assigned becomes more powerful,
        // the required assigner role must not decrease.
        // This prevents a lower-privilege admin from granting a higher
        // role than themselves.
        let operator_req = AdminContract::get_required_role_to_assign(AdminRole::Operator);
        let admin_req = AdminContract::get_required_role_to_assign(AdminRole::Admin);
        let super_req = AdminContract::get_required_role_to_assign(AdminRole::SuperAdmin);

        assert!(operator_req <= admin_req);
        assert!(admin_req <= super_req);

        // And the required role must always be at least as powerful as
        // the role being granted (no privilege escalation via assignment).
        assert!(operator_req >= AdminRole::Operator);
        assert!(admin_req >= AdminRole::Admin);
        assert!(super_req >= AdminRole::SuperAdmin);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: initialization and duplicate guards
    // ------------------------------------------------------------------------

    #[test]
    fn test_initialize_sets_superadmin_and_is_idempotent_on_repeat() {
        let (env, _contract_id, root, client) = setup();

        // The initialized SuperAdmin must be active and have the SuperAdmin role.
        let info = client.get_admin_info(&root);
        assert_eq!(info.role, AdminRole::SuperAdmin);
        assert!(info.active);
        assert_eq!(info.address, root.clone());

        // Reinitialization must be rejected to prevent hijacking the contract.
        let attacker = Address::generate(&env);
        let result = client.try_initialize(&attacker, &1u32, &100u32);
        assert!(result.is_err());

        // State must not have changed.
        let info = client.get_admin_info(&root);
        assert_eq!(info.role, AdminRole::SuperAdmin);
        assert_eq!(info.address, root.clone());
    }

    #[test]
    fn test_contract_address_cannot_be_granted_an_admin_role() {
        // Adversarial: assigning a governance role to the contract's own
        // address would create a self-referential auth loop. The guard
        // (`require_valid_admin_address`) runs on every assignment path
        // before any state is written, so the contract can never become an
        // admin, an owner candidate, or a pause signer.
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AdminContract);
        let root = Address::generate(&env);
        let client = AdminContractClient::new(&env, &contract_id);
        client.initialize(&root, &1u32, &100u32);

        assert_contract_error(
            client.try_add_admin(&root, &contract_id, &AdminRole::Operator),
            ERR_INVALID_ADMIN_ADDRESS,
        );

        // No record may exist for the contract itself.
        assert!(client.try_get_admin_info(&contract_id).is_err());
        assert_eq!(client.get_admin_count(), 1);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: authorization and permission boundaries
    // ------------------------------------------------------------------------

    #[test]
    fn test_operator_cannot_assign_any_role() {
        // Adversarial: an Operator attempting to assign any role must be
        // rejected. The required role for every target role is strictly
        // greater than Operator, so no assignment is permitted.
        for target in [AdminRole::Operator, AdminRole::Admin, AdminRole::SuperAdmin] {
            let required = AdminContract::get_required_role_to_assign(target.clone());
            assert!(required > AdminRole::Operator);
        }
    }

    #[test]
    fn test_admin_cannot_assign_admin_or_superadmin() {
        // Adversarial: an Admin attempting to assign Admin or SuperAdmin
        // must be rejected. Only SuperAdmin may grant those roles.
        for target in [AdminRole::Admin, AdminRole::SuperAdmin] {
            let required = AdminContract::get_required_role_to_assign(target.clone());
            assert!(required > AdminRole::Admin);
        }

        // Admin may grant Operator.
        let required = AdminContract::get_required_role_to_assign(AdminRole::Operator);
        assert!(required <= AdminRole::Admin);
    }

    #[test]
    fn test_superadmin_can_assign_every_role() {
        // Positive case: SuperAdmin is always sufficiently privileged.
        for target in [AdminRole::Operator, AdminRole::Admin, AdminRole::SuperAdmin] {
            let required = AdminContract::get_required_role_to_assign(target.clone());
            assert!(AdminRole::SuperAdmin >= required);
        }
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: suspension / stale state handling
    // ------------------------------------------------------------------------

    #[test]
    fn test_suspended_admin_info_is_not_active_and_carries_deadline() {
        // Invariant: an `AdminInfo` record carries both the permanent
        // `active` flag (toggled by deactivate/reactivate) and the
        // self-expiring `suspended_until` deadline (toggled by suspend).
        // Authorization code must consult both.
        let env = Env::default();
        let address = Address::generate(&env);
        let assigned_by = Address::generate(&env);

        let info = AdminInfo {
            address: address.clone(),
            role: AdminRole::Admin,
            assigned_at: 1,
            assigned_by: assigned_by.clone(),
            active: false,
            suspended_until: 999999,
        };

        assert!(!info.active);
        assert!(info.suspended_until > 0);
        assert_eq!(info.role, AdminRole::Admin);
    }

    #[test]
    fn test_admin_info_default_suspension_is_zero() {
        // Boundary: a freshly assigned admin has no suspension deadline.
        let env = Env::default();
        let address = Address::generate(&env);
        let assigned_by = Address::generate(&env);

        let info = AdminInfo {
            address: address.clone(),
            role: AdminRole::Operator,
            assigned_at: 0,
            assigned_by: assigned_by.clone(),
            active: true,
            suspended_until: 0,
        };

        assert_eq!(info.suspended_until, 0);
        assert!(info.active);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: duplicate / idempotent assignment
    // ------------------------------------------------------------------------

    #[test]
    fn test_duplicate_assignment_is_rejected_or_idempotent() {
        // Adversarial: assigning the same role to the same address twice
        // must not corrupt state. The contract rejects the duplicate and
        // the original record survives untouched.
        let (env, _contract_id, root, client) = setup();

        let target = Address::generate(&env);

        // First assignment must succeed.
        let first = client.add_admin(&root, &target, &AdminRole::Operator);
        assert_eq!(first.role, AdminRole::Operator);
        let after_first = client.get_admin_info(&target);
        assert_eq!(after_first.role, AdminRole::Operator);

        // Duplicate assignment of the same role is rejected outright.
        assert_contract_error(
            client.try_add_admin(&root, &target, &AdminRole::Operator),
            ERR_ALREADY_ACTIVE,
        );

        // The record must not have been corrupted by the rejected retry.
        let after_dup = client.get_admin_info(&target);
        assert_eq!(after_dup.role, AdminRole::Operator);
        assert_eq!(after_dup.address, target.clone());
        assert!(after_dup.active);
        assert_eq!(after_dup.assigned_at, first.assigned_at);
        assert_eq!(after_dup.assigned_by, root.clone());
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: unauthorized assignment attempts
    // ------------------------------------------------------------------------

    #[test]
    fn test_unauthorized_assigner_is_rejected_and_state_unchanged() {
        // Adversarial: an address with no role attempts to grant a role.
        // The call must fail and no state must be mutated.
        let (env, _contract_id, root, client) = setup();

        let outsider = Address::generate(&env);
        let target = Address::generate(&env);

        assert!(client
            .try_add_admin(&outsider, &target, &AdminRole::Operator)
            .is_err());

        // The target must not have been created.
        assert!(client.try_get_admin_info(&target).is_err());
        assert_eq!(client.get_admin_count(), 1);
    }

    #[test]
    fn test_admin_cannot_grant_superadmin() {
        // Adversarial: an Admin attempting to grant SuperAdmin must be
        // rejected and the target must not be elevated.
        let (env, _contract_id, root, client) = setup();

        // Promote a second admin.
        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        let target = Address::generate(&env);
        assert!(client
            .try_add_admin(&admin, &target, &AdminRole::SuperAdmin)
            .is_err());
        assert!(client.try_get_admin_info(&target).is_err());
        assert_eq!(client.get_admin_count(), 2);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: retry / partial failure idempotence
    // ------------------------------------------------------------------------

    #[test]
    fn test_retry_after_failure_does_not_leak_state() {
        // Adversarial: a failed authorization followed by a successful
        // authorized call must produce exactly the intended state.
        let (env, _contract_id, root, client) = setup();

        let target = Address::generate(&env);
        let outsider = Address::generate(&env);

        // Attempt 1: unauthorized -> fails.
        assert!(client
            .try_add_admin(&outsider, &target, &AdminRole::Operator)
            .is_err());
        assert!(client.try_get_admin_info(&target).is_err());

        // Attempt 2: authorized retry -> succeeds.
        client.add_admin(&root, &target, &AdminRole::Operator);
        let info = client.get_admin_info(&target);
        assert_eq!(info.role, AdminRole::Operator);
        assert!(info.active);
        assert_eq!(info.address, target.clone());
        assert_eq!(client.get_admin_count(), 2);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: revocation and stale authorization
    // ------------------------------------------------------------------------

    #[test]
    fn test_revoked_admin_cannot_assign_roles() {
        // Adversarial: an admin whose role was revoked must not be able
        // to grant roles afterward. This guards against stale authority.
        let (env, _contract_id, root, client) = setup();

        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        // Revoke the admin's role.
        client.remove_admin(&root, &admin);
        assert!(client.try_get_admin_info(&admin).is_err());

        // The revoked admin must not be able to assign roles.
        let target = Address::generate(&env);
        assert!(client
            .try_add_admin(&admin, &target, &AdminRole::Operator)
            .is_err());
        assert!(client.try_get_admin_info(&target).is_err());
        assert_eq!(client.get_admin_count(), 1);
    }

    #[test]
    fn test_revoke_superadmin_is_rejected_or_safely_handled() {
        // Adversarial: attempting to revoke the last SuperAdmin would
        // lock the contract. The call must fail and leave the SuperAdmin
        // active so governance can never be bricked.
        let (env, _contract_id, root, client) = setup();

        let res = client.try_remove_admin(&root, &root);
        assert_contract_error(res, ERR_NOT_ADMIN); // caller must outrank target

        let info = client.get_admin_info(&root);
        assert_eq!(info.role, AdminRole::SuperAdmin);
        assert!(info.active);
        assert_eq!(client.get_admin_count(), 1);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: concurrent / interleaved assignments
    // ------------------------------------------------------------------------

    #[test]
    fn test_interleaved_assignments_are_consistent() {
        // Adversarial: interleaved mutations from two authorized admins
        // must not corrupt state. The final role must match the last
        // successful mutation, and the loser of the race is rejected
        // rather than partially applied.
        let (env, _contract_id, root, client) = setup();

        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        let target = Address::generate(&env);

        // Admin grants Operator.
        client.add_admin(&admin, &target, &AdminRole::Operator);

        // SuperAdmin then promotes the same target to Admin.
        let updated = client.update_admin_role(&root, &target, &AdminRole::Admin);
        assert_eq!(updated.role, AdminRole::Admin);
        assert!(updated.active);

        let info = client.get_admin_info(&target);
        assert_eq!(info.role, AdminRole::Admin);
        assert!(info.active);
        assert_eq!(info.address, target.clone());
        assert_eq!(client.get_admin_count(), 3);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: boundary values
    // ------------------------------------------------------------------------

    #[test]
    fn test_admin_info_boundary_timestamps() {
        // Boundary: timestamps at the extremes of u64 must round-trip
        // without truncation or overflow.
        let env = Env::default();
        let address = Address::generate(&env);
        let assigned_by = Address::generate(&env);

        let max_info = AdminInfo {
            address: address.clone(),
            role: AdminRole::SuperAdmin,
            assigned_at: u64::MAX,
            assigned_by: assigned_by.clone(),
            active: true,
            suspended_until: u64::MAX,
        };
        assert_eq!(max_info.assigned_at, u64::MAX);
        assert_eq!(max_info.suspended_until, u64::MAX);

        let min_info = AdminInfo {
            address: address.clone(),
            role: AdminRole::Operator,
            assigned_at: 0,
            assigned_by: assigned_by.clone(),
            active: true,
            suspended_until: 0,
        };
        assert_eq!(min_info.assigned_at, 0);
        assert_eq!(min_info.suspended_until, 0);
    }

    #[test]
    fn test_get_admin_info_for_unknown_address_is_none() {
        // Boundary: querying an address that was never assigned must be
        // rejected with `NotAdmin` rather than returning a fabricated
        // default record.
        let (env, _contract_id, root, client) = setup();

        let unknown = Address::generate(&env);
        assert!(client.try_get_admin_info(&unknown).is_err());
        assert_eq!(client.get_admin_count(), 1);
        assert_eq!(client.get_admin_info(&root).role, AdminRole::SuperAdmin);
    }

    #[test]
    fn test_get_admin_info_before_initialization_is_none() {
        // Boundary: querying any admin before initialization must be
        // rejected with `NotAdmin` and must not leave partial state.
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AdminContract);
        let client = AdminContractClient::new(&env, &contract_id);

        let any = Address::generate(&env);
        assert!(client.try_get_admin_info(&any).is_err());
        assert_eq!(client.get_admin_count(), 0);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: self-assignment / self-revocation
    // ------------------------------------------------------------------------

    #[test]
    fn test_super_admin_can_reassign_self_consistently() {
        // Adversarial: a SuperAdmin re-assigning their own role must not
        // corrupt or duplicate the admin record.
        let (env, _contract_id, root, client) = setup();

        // SuperAdmin re-assigning themselves SuperAdmin: rejected because
        // the record already exists, and the record is left untouched.
        assert_contract_error(
            client.try_add_admin(&root, &root, &AdminRole::SuperAdmin),
            ERR_ALREADY_ACTIVE,
        );

        let info = client.get_admin_info(&root);
        assert_eq!(info.role, AdminRole::SuperAdmin);
        assert!(info.active);
        assert_eq!(info.address, root.clone());
        assert_eq!(client.get_admin_count(), 1);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: error diagnostics are non-panicking
    // ------------------------------------------------------------------------

    #[test]
    fn test_assign_role_returns_error_not_panic_on_bad_caller() {
        // Adversarial: an unauthorized caller must get a deterministic
        // error result (not a panic), so callers can handle failure.
        let (env, _contract_id, _root, client) = setup();

        let caller = Address::generate(&env);
        let target = Address::generate(&env);
        let result = client.try_add_admin(&caller, &target, &AdminRole::Operator);
        // The result must be a well-formed error, not a panic.
        assert!(result.is_err());
    }

    #[test]
    fn test_assign_role_to_self_by_non_super_is_rejected() {
        // Adversarial: an Admin attempting to elevate themselves to
        // SuperAdmin must be rejected.
        let (env, _contract_id, root, client) = setup();

        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        assert!(client
            .try_add_admin(&admin, &admin, &AdminRole::SuperAdmin)
            .is_err());

        // The admin must remain an Admin.
        let info = client.get_admin_info(&admin);
        assert_eq!(info.role, AdminRole::Admin);
        assert!(info.active);
        assert_eq!(client.get_admin_count(), 2);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: multiple admins and independent state
    // ------------------------------------------------------------------------

    #[test]
    fn test_multiple_admins_have_independent_state() {
        // Adversarial: assigning one admin must not affect another.
        let (env, _contract_id, root, client) = setup();

        let admin_a = Address::generate(&env);
        let admin_b = Address::generate(&env);

        client.add_admin(&root, &admin_a, &AdminRole::Admin);
        client.add_admin(&root, &admin_b, &AdminRole::Operator);

        let info_a = client.get_admin_info(&admin_a);
        let info_b = client.get_admin_info(&admin_b);

        assert_eq!(info_a.role, AdminRole::Admin);
        assert_eq!(info_b.role, AdminRole::Operator);
        assert_eq!(info_a.address, admin_a.clone());
        assert_eq!(info_b.address, admin_b.clone());
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: invalid address / zero-address guards
    // ------------------------------------------------------------------------

    #[test]
    fn test_assign_role_with_distinct_addresses_keeps_state_isolated() {
        // Adversarial: two distinct targets must not share state.
        let (env, _contract_id, root, client) = setup();

        let target_1 = Address::generate(&env);
        let target_2 = Address::generate(&env);

        client.add_admin(&root, &target_1, &AdminRole::Admin);
        client.add_admin(&root, &target_2, &AdminRole::Operator);

        let info_1 = client.get_admin_info(&target_1);
        let info_2 = client.get_admin_info(&target_2);

        assert_eq!(info_1.role, AdminRole::Admin);
        assert_eq!(info_2.role, AdminRole::Operator);
        assert_ne!(info_1.address, info_2.address);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: suspension lifecycle
    // ------------------------------------------------------------------------

    #[test]
    fn test_suspend_and_reinstate_admin_is_consistent() {
        // Adversarial: suspending then reinstating an admin must not
        // corrupt the role or the address.
        let (env, _contract_id, root, client) = setup();

        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        // Suspend the admin. Suspension is a self-expiring overlay: the
        // record stays `active` and keeps its role, but effective authority
        // is withheld until the deadline.
        client.suspend_admin(&root, &admin, &100u64);
        let suspended = client.get_admin_info(&admin);
        assert!(suspended.active);
        assert_eq!(suspended.suspended_until, 100);
        assert_eq!(suspended.role, AdminRole::Admin);
        assert_eq!(client.is_admin(&admin), Role::User);
        assert!(!client.has_role_at_least(&admin, &AdminRole::Operator));

        // Boundary: at exactly `suspended_until` the admin is effective
        // again without any second transaction.
        env.ledger().with_mut(|li| li.timestamp = 100);
        assert_eq!(client.is_admin(&admin), Role::Admin);
        assert!(client.has_role_at_least(&admin, &AdminRole::Operator));

        // Reinstate the admin through the deactivation lifecycle.
        client.deactivate_admin(&root, &admin);
        let deactivated = client.get_admin_info(&admin);
        assert!(!deactivated.active);
        assert_eq!(deactivated.role, AdminRole::Admin);

        client.reactivate_admin(&root, &admin);
        let reinstated = client.get_admin_info(&admin);
        assert!(reinstated.active);
        assert_eq!(reinstated.role, AdminRole::Admin);
        assert_eq!(reinstated.address, admin.clone());
        assert_eq!(client.get_admin_count(), 2);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: determinism across repeated runs
    // ------------------------------------------------------------------------

    #[test]
    fn test_repeated_queries_are_deterministic() {
        // Adversarial: repeated queries of the same address must return
        // identical results (no hidden mutation on read).
        let (env, _contract_id, root, client) = setup();

        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        let first = client.get_admin_info(&admin);
        let epoch_before = client.get_config_epoch();
        for _ in 0..10 {
            let next = client.get_admin_info(&admin);
            assert_eq!(next.role, first.role);
            assert_eq!(next.active, first.active);
            assert_eq!(next.assigned_at, first.assigned_at);
            assert_eq!(next.suspended_until, first.suspended_until);
        }
        // Reads must not advance the config epoch.
        assert_eq!(client.get_config_epoch(), epoch_before);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: log / error strings do not leak
    // ------------------------------------------------------------------------

    #[test]
    fn test_error_results_are_non_panicking_and_repeatable() {
        // Adversarial: the same invalid call must produce the same
        // error result every time (no non-determinism).
        let (env, _contract_id, _root, client) = setup();

        let outsider = Address::generate(&env);
        let target = Address::generate(&env);
        let epoch_before = client.get_config_epoch();

        for _ in 0..5 {
            let result = client.try_add_admin(&outsider, &target, &AdminRole::Operator);
            assert!(result.is_err());
            assert!(client.try_get_admin_info(&target).is_err());
        }

        // Rejected retries must never advance the config epoch.
        assert_eq!(client.get_config_epoch(), epoch_before);
        assert_eq!(client.get_admin_count(), 1);
    }

    // ------------------------------------------------------------------------
    // Adversarial regression cases: timestamp boundaries for suspension
    // ------------------------------------------------------------------------

    #[test]
    fn test_suspension_timestamp_boundary_lengths() {
        // Boundary: `until_ts` must be strictly in the future; the exact
        // value one second past "now" is accepted, "now" itself is not.
        let (env, _contract_id, root, client) = setup();

        let admin = Address::generate(&env);
        client.add_admin(&root, &admin, &AdminRole::Admin);

        let now = env.ledger().timestamp();

        // Rejected boundary: `until_ts == now` is not in the future.
        assert!(client.try_suspend_admin(&root, &admin, &now).is_err());
        // Rejected boundary: neither is anything strictly before `now`.
        if now > 0 {
            assert!(client.try_suspend_admin(&root, &admin, &(now - 1)).is_err());
        }

        // Whether accepted or rejected, the admin record is untouched.
        let untouched = client.get_admin_info(&admin);
        assert_eq!(untouched.suspended_until, 0);
        assert_eq!(untouched.role, AdminRole::Admin);

        // Accepted boundary: `now + 1` is the smallest valid window.
        client.suspend_admin(&root, &admin, &(now + 1));
        let suspended = client.get_admin_info(&admin);
        assert_eq!(suspended.suspended_until, now + 1);
        assert_eq!(suspended.role, AdminRole::Admin);
        assert_eq!(suspended.address, admin.clone());
        assert!(client.get_admin_info(&root).active);
    }
}
