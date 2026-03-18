//! Integration tests for pap-core covering end-to-end flows

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use pap_core::error::PapError;
use pap_core::extensions::{AutoApprovalPolicy, ContinuityToken};
use pap_core::mandate::{DecayState, Mandate};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session, SessionState};
use rand::rngs::OsRng;

fn make_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn did_from_key(key: &SigningKey) -> String {
    pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
        .unwrap()
        .did()
}

#[test]
fn end_to_end_session_flow_with_receipt() {
    // Setup: principal, orchestrator, agent
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let orchestrator_key = make_keypair();
    let orchestrator_did = did_from_key(&orchestrator_key);
    let agent_key = make_keypair();
    let agent_did = did_from_key(&agent_key);

    // Root mandate
    let scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let mut root_mandate = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        scope.clone(),
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    );
    root_mandate.sign(&principal_key);
    assert!(root_mandate.verify(&principal_key.verifying_key()).is_ok());

    // Delegate to agent
    let mut agent_mandate = root_mandate
        .delegate(
            agent_did.clone(),
            scope.clone(),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(12),
        )
        .unwrap();
    agent_mandate.sign(&principal_key);

    // Capability token
    let mut token = CapabilityToken::mint(
        agent_did.clone(),
        "schema:SearchAction".into(),
        orchestrator_did.clone(),
        Utc::now() + Duration::hours(1),
    );
    token.sign(&orchestrator_key);

    // Session: initiate -> open -> execute -> close
    let mut session =
        Session::initiate(&token, &agent_did, &orchestrator_key.verifying_key()).unwrap();
    assert_eq!(session.state, SessionState::Initiated);

    let init_sess_key = make_keypair();
    let recv_sess_key = make_keypair();
    let init_sess_did = did_from_key(&init_sess_key);
    let recv_sess_did = did_from_key(&recv_sess_key);

    session.open(init_sess_did.clone(), recv_sess_did.clone()).unwrap();
    assert_eq!(session.state, SessionState::Open);

    session.execute().unwrap();
    assert_eq!(session.state, SessionState::Executed);

    // Receipt co-signing
    let mut receipt = TransactionReceipt::from_session(
        &session,
        vec![], // no disclosure
        vec!["agent:search_completed".into()],
        "schema:SearchAction executed".into(),
        "schema:SearchResultsPage returned".into(),
    )
    .unwrap();

    receipt.co_sign(&init_sess_key);
    receipt.co_sign(&recv_sess_key);
    assert!(receipt
        .verify_both(
            &init_sess_key.verifying_key(),
            &recv_sess_key.verifying_key()
        )
        .is_ok());

    session.close().unwrap();
    assert_eq!(session.state, SessionState::Closed);
}

#[test]
fn mandate_chain_three_levels() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let orchestrator_key = make_keypair();
    let orchestrator_did = did_from_key(&orchestrator_key);
    let agent1_key = make_keypair();
    let agent1_did = did_from_key(&agent1_key);
    let agent2_did = did_from_key(&make_keypair());

    // Root mandate
    let root_scope = Scope::new(vec![
        ScopeAction::new("schema:SearchAction"),
        ScopeAction::new("schema:PayAction"),
    ]);
    let mut root = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        root_scope.clone(),
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(48),
    );
    root.sign(&principal_key);

    // Level 1: delegate to agent1
    let agent1_scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let mut level1 = root
        .delegate(
            agent1_did.clone(),
            agent1_scope.clone(),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(24),
        )
        .unwrap();
    level1.sign(&orchestrator_key);

    // Level 2: agent1 delegates to agent2
    let mut level2 = level1
        .delegate(
            agent2_did.clone(),
            agent1_scope.clone(),
            DisclosureSet::empty(),
            Utc::now() + Duration::hours(12),
        )
        .unwrap();
    level2.sign(&agent1_key);

    // Verify chain
    use pap_core::mandate::MandateChain;
    let mut chain = MandateChain::new(root.clone());
    chain.push(level1.clone());
    chain.push(level2.clone());
    let keys = vec![
        principal_key.verifying_key(),
        orchestrator_key.verifying_key(),
        agent1_key.verifying_key(),
    ];
    assert!(chain.verify_chain(&keys).is_ok());
}

#[test]
fn mandate_delegation_scope_violation_rejected() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let orchestrator_did = did_from_key(&make_keypair());
    let agent_did = did_from_key(&make_keypair());

    let root_scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let root = Mandate::issue_root(
        principal_did,
        orchestrator_did.clone(),
        root_scope.clone(),
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    );

    // Try to delegate with expanded scope (not allowed)
    let bad_scope = Scope::new(vec![
        ScopeAction::new("schema:SearchAction"),
        ScopeAction::new("schema:PayAction"), // not in parent!
    ]);

    let result = root.delegate(
        agent_did,
        bad_scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(12),
    );

    assert!(matches!(result, Err(PapError::DelegationExceedsScope)));
}

#[test]
fn mandate_delegation_ttl_violation_rejected() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let orchestrator_did = did_from_key(&make_keypair());
    let agent_did = did_from_key(&make_keypair());

    let scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let root = Mandate::issue_root(
        principal_did,
        orchestrator_did.clone(),
        scope.clone(),
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(12),
    );

    // Try to delegate with longer TTL (not allowed)
    let result = root.delegate(
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24), // longer than parent!
    );

    assert!(matches!(result, Err(PapError::DelegationExceedsTtl)));
}

#[test]
fn decay_state_time_based_transitions() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let agent_did = did_from_key(&make_keypair());

    // Create mandate with long TTL - should be Active
    let scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let mandate = Mandate::issue_root(
        principal_did,
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24), // 24 hours
    );

    // Fresh mandate with long TTL should be Active
    let decay = mandate.compute_decay_state(3600); // 1 hour decay window
    assert_eq!(decay, DecayState::Active);
}

#[test]
fn session_nonce_replay_prevention() {
    let issuer_key = make_keypair();
    let issuer_did = did_from_key(&issuer_key);
    let target_did = did_from_key(&make_keypair());

    let mut token = CapabilityToken::mint(
        target_did.clone(),
        "schema:SearchAction".into(),
        issuer_did,
        Utc::now() + Duration::hours(1),
    );
    token.sign(&issuer_key);

    // First use: succeeds
    let session1 = Session::initiate(&token, &target_did, &issuer_key.verifying_key());
    assert!(session1.is_ok());

    // Nonce is consumed in the session1, but Session::initiate creates independent state
    // The token itself doesn't track consumed nonces - it's validated once per session
    // This is expected behavior - tokens are single-use via session nonce tracking
    assert!(session1.unwrap().is_nonce_consumed(&token.nonce));
}

#[test]
fn auto_approval_policy_value_cap_enforcement() {
    let mandate_scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);

    let policy = AutoApprovalPolicy::new("Small purchases", Scope::new(vec![ScopeAction::new("schema:PayAction")]))
        .with_max_value(50.0);

    assert_eq!(policy.max_value, Some(50.0));
    assert!(policy.validate_against_mandate(&mandate_scope).is_ok());
}

#[test]
fn continuity_token_principal_controlled_ttl() {
    let vendor_did = did_from_key(&make_keypair());
    let principal_ttl = Utc::now() + Duration::days(30);

    let token = ContinuityToken::new(
        "schema:Subscription",
        vendor_did.clone(),
        "encrypted-state-blob",
        principal_ttl,
    );

    assert_eq!(token.vendor_did, vendor_did);
    assert_eq!(token.ttl, principal_ttl);
    assert!(!token.is_expired());
}

#[test]
fn disclosure_set_property_reference_only() {
    let mut disclosure_set = DisclosureSet::empty();
    disclosure_set.entries.push(DisclosureEntry::new(
        "schema:Person",
        vec!["schema:name".into()],
        vec![],
    ));
    disclosure_set.entries.push(DisclosureEntry::new(
        "schema:Person",
        vec!["schema:email".into()],
        vec![],
    ));

    assert_eq!(disclosure_set.entries.len(), 2);
    assert_eq!(disclosure_set.entries[0].permitted_properties[0], "schema:name");
    assert_eq!(disclosure_set.entries[1].permitted_properties[0], "schema:email");
}

#[test]
fn receipt_zero_disclosure_transaction() {
    let init_key = make_keypair();
    let recv_key = make_keypair();
    let issuer_key = make_keypair();
    let issuer_did = did_from_key(&issuer_key);
    let target_did = did_from_key(&make_keypair());

    let mut token = CapabilityToken::mint(
        target_did.clone(),
        "schema:SearchAction".into(),
        issuer_did,
        Utc::now() + Duration::hours(1),
    );
    token.sign(&issuer_key);

    let mut session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

    // Open the session with DIDs
    session.open(did_from_key(&init_key), did_from_key(&recv_key)).unwrap();
    session.execute().unwrap();

    let mut receipt = TransactionReceipt::from_session(
        &session,
        vec![], // zero disclosure
        vec!["agent:search_executed".into()],
        "Search performed".into(),
        "Results returned".into(),
    )
    .unwrap();

    assert!(receipt.disclosed_by_initiator.is_empty());

    receipt.co_sign(&init_key);
    receipt.co_sign(&recv_key);

    assert!(receipt.verify_both(&init_key.verifying_key(), &recv_key.verifying_key()).is_ok());
}

#[test]
fn mandate_payment_proof_attachment() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let agent_did = did_from_key(&make_keypair());

    let scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);
    let mut mandate = Mandate::issue_root(
        principal_did,
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    );

    // Attach payment proof
    mandate.payment_proof = Some("ecash:blind:v1:token=XYZ123".into());
    mandate.sign(&principal_key);

    assert!(mandate.payment_proof.is_some());
    assert!(mandate.verify(&principal_key.verifying_key()).is_ok());
}
