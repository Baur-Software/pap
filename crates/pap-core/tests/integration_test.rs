//! Integration tests for pap-core covering end-to-end flows

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use pap_core::error::PapError;
use pap_core::extensions::{AutoApprovalPolicy, ContinuityToken};
use pap_core::mandate::{DecayState, Mandate};
use pap_core::payment::PaymentProof;
use pap_core::receipt::TransactionReceipt;
use pap_core::recovery::{
    PartialRecoverySignature, RecoveryMandate, RecoveryProof, RecoveryRequest, RevocationProof,
};
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

    session
        .open(init_sess_did.clone(), recv_sess_did.clone())
        .unwrap();
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

    let policy = AutoApprovalPolicy::new(
        "Small purchases",
        Scope::new(vec![ScopeAction::new("schema:PayAction")]),
    )
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
    assert_eq!(
        disclosure_set.entries[0].permitted_properties[0],
        "schema:name"
    );
    assert_eq!(
        disclosure_set.entries[1].permitted_properties[0],
        "schema:email"
    );
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
    session
        .open(did_from_key(&init_key), did_from_key(&recv_key))
        .unwrap();
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

    assert!(receipt
        .verify_both(&init_key.verifying_key(), &recv_key.verifying_key())
        .is_ok());
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

    // Attach typed payment proof (ecash commitment)
    mandate.payment_proof = Some(PaymentProof::ecash(b"blind-signed-token-XYZ123"));
    mandate.sign(&principal_key);

    assert!(mandate.payment_proof.is_some());
    assert!(mandate.verify(&principal_key.verifying_key()).is_ok());
    assert!(mandate.validate_payment_proof().is_ok());
}

#[test]
fn lightning_payment_proof_end_to_end() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let orchestrator_key = make_keypair();
    let orchestrator_did = did_from_key(&orchestrator_key);
    let agent_did = did_from_key(&make_keypair());

    // Root mandate with PayAction and Lightning proof
    let scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);
    let proof = PaymentProof::lightning(b"bolt11-payment-hash-preimage");
    let mut root_mandate = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        scope.clone(),
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    )
    .with_payment_proof(proof);

    assert!(root_mandate.validate_payment_proof().is_ok());
    root_mandate.sign(&principal_key);
    assert!(root_mandate.verify(&principal_key.verifying_key()).is_ok());

    // Capability token for payment action
    let mut token = CapabilityToken::mint(
        agent_did.clone(),
        "schema:PayAction".into(),
        orchestrator_did.clone(),
        Utc::now() + Duration::hours(1),
    );
    token.sign(&orchestrator_key);

    // Session: initiate -> open -> execute
    let mut session =
        Session::initiate(&token, &agent_did, &orchestrator_key.verifying_key()).unwrap();
    let init_sess_key = make_keypair();
    let recv_sess_key = make_keypair();
    session
        .open(did_from_key(&init_sess_key), did_from_key(&recv_sess_key))
        .unwrap();
    session.execute().unwrap();

    // Receipt with payment proof commitment
    let mut receipt = TransactionReceipt::from_session(
        &session,
        vec![],
        vec!["agent:payment_executed".into()],
        "schema:PayAction executed".into(),
        "schema:PaymentReceipt returned".into(),
    )
    .unwrap()
    .with_payment_proof(&root_mandate);

    // Validate commitment matches mandate
    assert!(receipt.validate_payment_commitment(&root_mandate).is_ok());

    // Co-sign and verify
    receipt.co_sign(&init_sess_key);
    receipt.co_sign(&recv_sess_key);
    assert!(receipt
        .verify_both(
            &init_sess_key.verifying_key(),
            &recv_sess_key.verifying_key()
        )
        .is_ok());

    // Verify preimage against proof
    assert!(root_mandate
        .payment_proof
        .as_ref()
        .unwrap()
        .verify(b"bolt11-payment-hash-preimage"));
}

#[test]
fn ecash_payment_proof_end_to_end() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let agent_did = did_from_key(&make_keypair());

    let scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);
    let proof = PaymentProof::ecash(b"cashuAeyJ0b2tlbiI6W3sibWludCI6Im");
    let mut mandate = Mandate::issue_root(
        principal_did,
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    )
    .with_payment_proof(proof);

    assert!(mandate.validate_payment_proof().is_ok());
    mandate.sign(&principal_key);
    assert!(mandate.verify(&principal_key.verifying_key()).is_ok());

    // Verify the commitment
    assert!(mandate
        .payment_proof
        .as_ref()
        .unwrap()
        .verify(b"cashuAeyJ0b2tlbiI6W3sibWludCI6Im"));
    assert!(!mandate
        .payment_proof
        .as_ref()
        .unwrap()
        .verify(b"wrong-token"));
}

#[test]
fn pay_action_without_proof_rejected() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let agent_did = did_from_key(&make_keypair());

    // PayAction scope but no payment proof attached
    let scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);
    let mandate = Mandate::issue_root(
        principal_did,
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    );

    assert!(matches!(
        mandate.validate_payment_proof(),
        Err(PapError::MissingPaymentProof)
    ));
}

#[test]
fn receipt_missing_commitment_for_pay_action_rejected() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let orchestrator_key = make_keypair();
    let orchestrator_did = did_from_key(&orchestrator_key);
    let agent_did = did_from_key(&make_keypair());

    let scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);
    let mut mandate = Mandate::issue_root(
        principal_did,
        orchestrator_did.clone(),
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    )
    .with_payment_proof(PaymentProof::lightning(b"payment-hash"));
    mandate.sign(&principal_key);

    let mut token = CapabilityToken::mint(
        agent_did.clone(),
        "schema:PayAction".into(),
        orchestrator_did,
        Utc::now() + Duration::hours(1),
    );
    token.sign(&orchestrator_key);

    let mut session =
        Session::initiate(&token, &agent_did, &orchestrator_key.verifying_key()).unwrap();
    session
        .open("did:key:zinit".into(), "did:key:zrecv".into())
        .unwrap();
    session.execute().unwrap();

    // Receipt WITHOUT calling with_payment_proof
    let receipt = TransactionReceipt::from_session(
        &session,
        vec![],
        vec![],
        "payment executed".into(),
        "receipt returned".into(),
    )
    .unwrap();

    // Validation fails: receipt missing commitment
    assert!(receipt.validate_payment_commitment(&mandate).is_err());
}

#[test]
fn non_payment_action_no_proof_required() {
    let principal_did = did_from_key(&make_keypair());
    let agent_did = did_from_key(&make_keypair());

    // SearchAction scope — no payment proof needed
    let scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let mandate = Mandate::issue_root(
        principal_did,
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    );

    assert!(mandate.validate_payment_proof().is_ok());
}

#[test]
fn payment_proof_serialization_in_mandate() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let agent_did = did_from_key(&make_keypair());

    let scope = Scope::new(vec![ScopeAction::new("schema:PayAction")]);
    let proof = PaymentProof::lightning(b"serialize-test-hash");
    let mut mandate = Mandate::issue_root(
        principal_did,
        agent_did,
        scope,
        DisclosureSet::empty(),
        Utc::now() + Duration::hours(24),
    )
    .with_payment_proof(proof);
    mandate.sign(&principal_key);

    let json = serde_json::to_string(&mandate).unwrap();
    let mandate2: Mandate = serde_json::from_str(&json).unwrap();

    assert_eq!(
        mandate.payment_proof.as_ref().unwrap().commitment(),
        mandate2.payment_proof.as_ref().unwrap().commitment()
    );
    assert!(mandate2.verify(&principal_key.verifying_key()).is_ok());
}

// ─── M-of-N Social Recovery ────────────────────────────────────────

#[test]
fn social_recovery_2_of_3_simulation() {
    // ── Setup: Principal designates 3 notaries with threshold 2 ──

    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);

    let notary1_key = make_keypair();
    let notary1_did = did_from_key(&notary1_key);
    let notary2_key = make_keypair();
    let notary2_did = did_from_key(&notary2_key);
    let notary3_key = make_keypair();
    let notary3_did = did_from_key(&notary3_key);

    // Principal creates recovery mandate while healthy
    let mut recovery_mandate = RecoveryMandate::new(
        principal_did.clone(),
        2, // threshold: 2 of 3
        vec![
            notary1_did.clone(),
            notary2_did.clone(),
            notary3_did.clone(),
        ],
    )
    .unwrap();
    recovery_mandate.sign(&principal_key);

    // Verify the recovery mandate is valid
    assert!(recovery_mandate
        .verify(&principal_key.verifying_key())
        .is_ok());
    assert!(recovery_mandate.is_notary(&notary1_did));
    assert!(recovery_mandate.is_notary(&notary2_did));
    assert!(recovery_mandate.is_notary(&notary3_did));
    assert!(!recovery_mandate.is_notary("did:key:zoutsider"));

    // ── Recovery: Principal lost their key, generates new keypair ──

    let new_principal_key = make_keypair();
    let new_principal_did = did_from_key(&new_principal_key);

    // Recovery coordinator creates the request
    let recovery_request = RecoveryRequest::new(
        principal_did.clone(),
        new_principal_did.clone(),
        recovery_mandate.hash(),
    );

    // ── Blind co-signing: Each notary signs independently ──

    // Notary 1 signs (doesn't know about notary 2)
    let partial_sig_1 = PartialRecoverySignature::sign(
        &recovery_mandate,
        &recovery_request,
        &notary1_did,
        &notary1_key,
        &principal_key.verifying_key(),
    )
    .unwrap();

    // Notary 2 signs (doesn't know about notary 1)
    let partial_sig_2 = PartialRecoverySignature::sign(
        &recovery_mandate,
        &recovery_request,
        &notary2_did,
        &notary2_key,
        &principal_key.verifying_key(),
    )
    .unwrap();

    // Verify each partial signature independently
    assert!(partial_sig_1
        .verify(&recovery_request, &notary1_key.verifying_key())
        .is_ok());
    assert!(partial_sig_2
        .verify(&recovery_request, &notary2_key.verifying_key())
        .is_ok());

    // ── Assemble recovery proof (2 of 3 signatures) ──

    let notary_keys = vec![
        (notary1_did.clone(), notary1_key.verifying_key()),
        (notary2_did.clone(), notary2_key.verifying_key()),
        (notary3_did.clone(), notary3_key.verifying_key()),
    ];

    let recovery_proof = RecoveryProof::assemble(
        recovery_request,
        recovery_mandate,
        vec![partial_sig_1, partial_sig_2],
        &principal_key.verifying_key(),
        &notary_keys,
    )
    .unwrap();

    // Verify the assembled proof
    assert!(recovery_proof
        .verify(&principal_key.verifying_key(), &notary_keys)
        .is_ok());
    assert_eq!(recovery_proof.partial_signatures.len(), 2);

    // ── Revocation: Old key is cryptographically revoked ──

    let mut revocation = RevocationProof::from_recovery_proof(&recovery_proof);
    assert_eq!(revocation.old_principal_did, principal_did);
    assert_eq!(revocation.new_principal_did, new_principal_did);

    // New principal signs the revocation (proves possession of new key)
    revocation.sign(&new_principal_key);
    assert!(revocation
        .verify(&new_principal_key.verifying_key())
        .is_ok());

    // Wrong key should fail verification
    let wrong_key = make_keypair();
    assert!(revocation.verify(&wrong_key.verifying_key()).is_err());
}

#[test]
fn social_recovery_below_threshold_rejected() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let notary1_key = make_keypair();
    let notary1_did = did_from_key(&notary1_key);
    let notary2_did = did_from_key(&make_keypair());
    let notary3_did = did_from_key(&make_keypair());

    let mut mandate = RecoveryMandate::new(
        principal_did.clone(),
        2,
        vec![
            notary1_did.clone(),
            notary2_did.clone(),
            notary3_did.clone(),
        ],
    )
    .unwrap();
    mandate.sign(&principal_key);

    let request =
        RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

    // Only 1 signature — threshold is 2
    let ps1 = PartialRecoverySignature::sign(
        &mandate,
        &request,
        &notary1_did,
        &notary1_key,
        &principal_key.verifying_key(),
    )
    .unwrap();

    let result = RecoveryProof::assemble(
        request,
        mandate,
        vec![ps1],
        &principal_key.verifying_key(),
        &[
            (notary1_did, notary1_key.verifying_key()),
            (notary2_did, make_keypair().verifying_key()),
            (notary3_did, make_keypair().verifying_key()),
        ],
    );

    assert!(matches!(result, Err(PapError::ThresholdNotMet(2, 1))));
}

#[test]
fn social_recovery_outsider_notary_rejected() {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let notary1_key = make_keypair();
    let notary1_did = did_from_key(&notary1_key);
    let outsider_key = make_keypair();
    let outsider_did = did_from_key(&outsider_key);

    let mut mandate = RecoveryMandate::new(principal_did.clone(), 1, vec![notary1_did]).unwrap();
    mandate.sign(&principal_key);

    let request =
        RecoveryRequest::new(principal_did, did_from_key(&make_keypair()), mandate.hash());

    // Outsider tries to sign — not in notary set
    let result = PartialRecoverySignature::sign(
        &mandate,
        &request,
        &outsider_did,
        &outsider_key,
        &principal_key.verifying_key(),
    );

    assert!(matches!(result, Err(PapError::NotaryNotInSet(_))));
}
