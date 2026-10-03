#![cfg(test)]

use dispute_resolution::{
    DisputeError, DisputeResolutionContract, DisputeResolutionContractClient,
};
use soroban_sdk::{testutils::Address as _, Address, Env};

fn client(env: &Env) -> DisputeResolutionContractClient<'_> {
    DisputeResolutionContractClient::new(env, &env.register(DisputeResolutionContract, ()))
}

#[test]
fn test_close_succeeds_for_resolver() {
    let env = Env::default();
    let resolver = Address::generate(&env);
    let client = client(&env);

    env.mock_all_auths();
    let dispute_id = client.create_dispute(&resolver);

    client.close(&resolver, &dispute_id);

    let dispute = client.get_dispute(&dispute_id);
    assert_eq!(dispute.status, dispute_resolution::DisputeStatus::Closed);
}

#[test]
fn test_double_close_fails() {
    let env = Env::default();
    let resolver = Address::generate(&env);
    let client = client(&env);

    env.mock_all_auths();
    let dispute_id = client.create_dispute(&resolver);

    client.close(&resolver, &dispute_id);

    let result = client.try_close(&resolver, &dispute_id);
    assert!(result.is_err());
    // Second close is rejected as AlreadyClosed, not silently repeated.
    assert_eq!(
        result,
        Err(Ok(DisputeError::AlreadyClosed)),
        "double close must report AlreadyClosed"
    );
}

#[test]
fn test_unauthorized_close_fails() {
    let env = Env::default();
    let resolver = Address::generate(&env);
    let attacker = Address::generate(&env);
    let client = client(&env);

    env.mock_all_auths();
    let dispute_id = client.create_dispute(&resolver);

    // A non-resolver caller (authenticated, but not the resolver) is rejected.
    let result = client.try_close(&attacker, &dispute_id);
    assert_eq!(
        result,
        Err(Ok(DisputeError::Unauthorized)),
        "only the resolver may close the dispute"
    );

    // The dispute is untouched by the rejected attempt.
    let dispute = client.get_dispute(&dispute_id);
    assert_eq!(dispute.status, dispute_resolution::DisputeStatus::Open);
}

#[test]
fn test_close_unknown_dispute_fails() {
    let env = Env::default();
    let resolver = Address::generate(&env);
    let client = client(&env);

    env.mock_all_auths();
    let result = client.try_close(&resolver, &42_u64);
    assert_eq!(result, Err(Ok(DisputeError::DisputeNotFound)));
}
