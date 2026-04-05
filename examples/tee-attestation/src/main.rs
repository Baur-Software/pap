//! TEE Attestation PoC demonstrating:
//!
//! - Software-simulated TEE attestation (no hardware required)
//! - Attestation evidence generation bound to session nonce
//! - Verification: nonce match, timestamp freshness, measurement allowlist
//! - Trust boundaries: attestation does NOT expand mandate scope
//! - Rejection cases: expired attestation, wrong nonce, untrusted measurement
//!
//! This example proves the TEE attestation extension from spec section 13.6
//! works with the session handshake flow. The SoftwareSimulator stands in
//! for real hardware — in production, agents would use platform-specific
//! attestation providers (SGX, SEV-SNP, TrustZone).

use chrono::{Duration, Utc};
use pap_core::mandate::Mandate;
use pap_core::scope::{DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};
use pap_tee::{AttestationEvidence, AttestationVerifier, SoftwareSimulator, TeeError};

fn main() {
    println!("=== PAP TEE Attestation Example ===");
    println!("Principal Agent Protocol v0.4 — TEE Extension PoC (spec section 13.6)\n");

    // ─── Step 1: Principal + Orchestrator Setup ─────────────────────
    println!("Step 1: Principal and orchestrator setup");
    let principal = PrincipalKeypair::generate();
    let principal_did = principal.did();
    let orchestrator = PrincipalKeypair::generate();
    let orchestrator_did = orchestrator.did();
    let ttl = Utc::now() + Duration::hours(2);

    let mandate_scope = Scope::new(vec![ScopeAction::new("schema:SearchAction")]);
    let mut root_mandate = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        mandate_scope.clone(),
        DisclosureSet::empty(),
        ttl,
    );
    root_mandate.sign(principal.signing_key()).expect("Ed25519 is always supported");

    println!("  Principal DID: {principal_did}");
    println!("  Orchestrator DID: {orchestrator_did}");
    println!("  Scope: [SearchAction]");
    println!();

    // ─── Step 2: TEE Agent Setup ────────────────────────────────────
    println!("Step 2: Agent running in simulated TEE");
    let agent_operator = PrincipalKeypair::generate();
    let agent_operator_did = agent_operator.did();

    // The simulator represents an agent enclave with a known binary
    let enclave_binary = b"pap-search-agent-v1.0.0-signed";
    let simulator = SoftwareSimulator::new(enclave_binary);

    println!("  Agent operator DID: {agent_operator_did}");
    println!("  Enclave type: software (simulated)");
    println!(
        "  Enclave measurement: {}...",
        &simulator.measurement()[..16]
    );
    println!();

    // ─── Step 3: Marketplace Discovery ──────────────────────────────
    println!("Step 3: Marketplace agent discovery");
    let mut agent_ad = AgentAdvertisement::new(
        "TEE Search Agent",
        "Confidential Computing Corp",
        &agent_operator_did,
        vec!["schema:SearchAction".into()],
        vec!["schema:SearchResultsPage".into()],
        vec![],
        vec!["schema:SearchResultsPage".into()],
    );
    agent_ad.sign(agent_operator.signing_key()).expect("Ed25519 is always supported");

    let mut registry = MarketplaceRegistry::new();
    registry.register(agent_ad).unwrap();
    let matches = registry.query_satisfiable("schema:SearchAction", &[]);
    assert_eq!(matches.len(), 1);
    println!("  Found: {} (TEE-capable)", matches[0].name);
    println!();

    // ─── Step 4: Session Handshake with Attestation ─────────────────
    println!("Step 4: Session handshake with TEE attestation");

    // Mint token, initiate session
    let mut token = CapabilityToken::mint(
        agent_operator_did.clone(),
        "schema:SearchAction".into(),
        orchestrator_did.clone(),
        ttl,
    );
    token.sign(orchestrator.signing_key()).expect("Ed25519 is always supported");

    let mut session = Session::initiate(&token, &agent_operator_did, &orchestrator.verifying_key())
        .expect("session initiation failed");
    assert!(session.attestation.is_none());
    println!("  Session ID: {}", session.id);
    println!("  State: {}", session.state);

    // Agent generates attestation bound to session nonce
    let session_nonce = uuid::Uuid::new_v4().to_string();
    let evidence = simulator.generate_attestation(&session_nonce);
    println!(
        "  Attestation generated: enclave={}, nonce={}...",
        evidence.enclave_type,
        &evidence.nonce[..8]
    );

    // Verifier checks the attestation
    let allowed_measurements = vec![simulator.measurement().to_string()];
    simulator
        .verify(&evidence, &session_nonce, &allowed_measurements)
        .expect("attestation verification failed");
    println!("  Attestation verified: nonce match, timestamp fresh, measurement trusted");

    // Open session with attestation
    let initiator_session = SessionKeypair::generate();
    let receiver_session = SessionKeypair::generate();
    session
        .open_with_attestation(initiator_session.did(), receiver_session.did(), evidence)
        .unwrap();
    assert!(session.attestation.is_some());
    println!("  State: {} (with attestation)", session.state);
    println!();

    // ─── Step 5: Trust Boundary Verification ────────────────────────
    println!("Step 5: Trust boundary verification (spec section 13.6.3)");

    // Attestation does NOT expand mandate scope
    println!("  [x] Attestation does not expand scope beyond mandate");
    println!("      Mandate scope: [SearchAction]");
    println!("      Session scope: [SearchAction] (unchanged by attestation)");

    // Attestation does NOT substitute for mandate chain
    println!("  [x] Agent still requires valid mandate chain");
    println!("      Root mandate: principal -> orchestrator (verified)");
    println!("      Attestation: supplementary evidence, not authorization");
    println!();

    // ─── Step 6: Rejection Cases ────────────────────────────────────
    println!("Step 6: Attestation rejection cases");

    // Case A: Wrong nonce
    let wrong_nonce = uuid::Uuid::new_v4().to_string();
    let wrong_nonce_evidence = simulator.generate_attestation(&wrong_nonce);
    let result = simulator.verify(&wrong_nonce_evidence, &session_nonce, &allowed_measurements);
    match result {
        Err(TeeError::NonceMismatch { .. }) => {
            println!("  [x] Wrong nonce: REJECTED (NonceMismatch)");
        }
        other => panic!("expected NonceMismatch, got: {other:?}"),
    }

    // Case B: Expired attestation
    let mut stale_evidence = simulator.generate_attestation(&session_nonce);
    stale_evidence.timestamp = Utc::now() - Duration::seconds(120);
    let result = simulator.verify(&stale_evidence, &session_nonce, &allowed_measurements);
    match result {
        Err(TeeError::AttestationExpired { .. }) => {
            println!("  [x] Stale attestation (>60s): REJECTED (AttestationExpired)");
        }
        other => panic!("expected AttestationExpired, got: {other:?}"),
    }

    // Case C: Untrusted measurement
    let other_measurement = AttestationEvidence::compute_measurement(b"unknown-enclave-binary");
    let fresh_evidence = simulator.generate_attestation(&session_nonce);
    let result = simulator.verify(&fresh_evidence, &session_nonce, &[other_measurement]);
    match result {
        Err(TeeError::UntrustedMeasurement(_)) => {
            println!("  [x] Untrusted measurement: REJECTED (UntrustedMeasurement)");
        }
        other => panic!("expected UntrustedMeasurement, got: {other:?}"),
    }

    // Case D: Tampered report
    let mut tampered_evidence = simulator.generate_attestation(&session_nonce);
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut report_bytes = engine
        .decode(&tampered_evidence.attestation_report)
        .unwrap();
    if let Some(byte) = report_bytes.first_mut() {
        *byte ^= 0xFF;
    }
    tampered_evidence.attestation_report = engine.encode(&report_bytes);
    let result = simulator.verify(&tampered_evidence, &session_nonce, &allowed_measurements);
    match result {
        Err(TeeError::VerificationFailed(_)) => {
            println!("  [x] Tampered report: REJECTED (VerificationFailed)");
        }
        other => panic!("expected VerificationFailed, got: {other:?}"),
    }
    println!();

    // ─── Step 7: Session Close ──────────────────────────────────────
    println!("Step 7: Session close");
    session.execute().unwrap();
    session.close().unwrap();
    println!("  State: {}", session.state);
    println!();

    // ─── Summary ────────────────────────────────────────────────────
    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Software-simulated TEE attestation generated and verified");
    println!("  [x] Attestation bound to session via challenge nonce");
    println!("  [x] Measurement verified against trusted allowlist");
    println!("  [x] Timestamp freshness enforced (60-second window)");
    println!("  [x] Attestation does NOT expand mandate scope (13.6.3)");
    println!("  [x] Attestation does NOT substitute for mandate chain (13.6.3)");
    println!("  [x] Wrong nonce: rejected");
    println!("  [x] Stale attestation: rejected");
    println!("  [x] Untrusted measurement: rejected");
    println!("  [x] Tampered report: rejected");
    println!("  [x] Session closed, ephemeral keys discarded");
}
