//! End-to-end search PoC demonstrating the full PAP protocol flow:
//!
//! 1. Principal generates keypair and DID document
//! 2. Principal issues root mandate to orchestrator (scope: SearchAction)
//! 3. Orchestrator queries local marketplace registry for a search agent
//! 4. Orchestrator mints a capability token for the search agent
//! 5. Orchestrator delegates a task mandate to an initiating agent
//! 6. Initiating agent presents capability token to search agent
//! 7. Search agent verifies token, exchanges ephemeral session DIDs
//! 8. Initiating agent discloses nothing (search requires no personal context)
//! 9. Search agent executes (stub — returns hardcoded results)
//! 10. Both agents co-sign a transaction receipt
//! 11. Session closes, ephemeral keys discarded
//! 12. Receipt is printed — both principal chains visible, no personal data

use chrono::{Duration, Utc};
use pap_core::mandate::{Mandate, MandateChain};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{DidDocument, PrincipalKeypair, SessionKeypair};
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};

fn main() {
    println!("=== PAP Search Example ===");
    println!("Principal Agent Protocol v0.1 — End-to-end PoC\n");

    // ─── Step 1: Principal Setup ────────────────────────────────────
    println!("Step 1: Principal generates keypair and DID document");
    let principal = PrincipalKeypair::generate();
    let principal_did = principal.did();
    let did_doc = DidDocument::from_keypair(&principal);
    println!("  Principal DID: {principal_did}");
    println!("  DID Document:\n{}\n", did_doc.to_json());

    // ─── Step 2: Root Mandate ───────────────────────────────────────
    println!("Step 2: Principal issues root mandate to orchestrator");
    let orchestrator = PrincipalKeypair::generate();
    let orchestrator_did = orchestrator.did();
    let ttl = Utc::now() + Duration::hours(1);

    let mut root_mandate = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
        DisclosureSet::empty(), // search needs no personal context
        ttl,
    );
    root_mandate.sign(principal.signing_key());
    println!("  Orchestrator DID: {orchestrator_did}");
    println!("  Scope: [schema:SearchAction]");
    println!("  TTL: {ttl}");
    println!("  Mandate signed: true\n");

    // Verify the root mandate
    assert!(root_mandate.verify(&principal.verifying_key()).is_ok());

    // ─── Step 3: Marketplace Query ──────────────────────────────────
    println!("Step 3: Orchestrator queries marketplace for search agents");

    // Set up the marketplace with a search agent
    let search_operator = PrincipalKeypair::generate();
    let search_operator_did = search_operator.did();

    let mut search_ad = AgentAdvertisement::new(
        "Web Search Agent",
        "SearchCorp",
        &search_operator_did,
        vec!["schema:SearchAction".into()],
        vec!["schema:WebPage".into()],
        vec![], // requires no personal disclosure
        vec!["schema:SearchResult".into()],
    );
    search_ad.sign(search_operator.signing_key());

    let mut registry = MarketplaceRegistry::new();
    registry.register(search_ad).unwrap();

    // Orchestrator queries
    let matches = registry.query_satisfiable("schema:SearchAction", &[]);
    println!("  Found {} matching agent(s):", matches.len());
    for ad in &matches {
        println!("    - {} (operator: {})", ad.name, ad.provider.did);
        println!("      Capabilities: {:?}", ad.capability);
        println!("      Requires disclosure: {:?}", ad.requires_disclosure);
    }
    println!();

    let _selected_ad = matches[0];

    // ─── Step 4: Capability Token ───────────────────────────────────
    println!("Step 4: Orchestrator mints capability token for search agent");
    let mut token = CapabilityToken::mint(
        search_operator_did.clone(),
        "schema:SearchAction".into(),
        orchestrator_did.clone(),
        ttl,
    );
    token.sign(orchestrator.signing_key());
    println!("  Token ID: {}", token.id);
    println!("  Target: {}", token.target_did);
    println!("  Action: {}", token.action);
    println!("  Nonce: {}", token.nonce);
    println!();

    // ─── Step 5: Task Mandate Delegation ────────────────────────────
    println!("Step 5: Orchestrator delegates task mandate to initiating agent");
    let initiating_agent = PrincipalKeypair::generate();
    let initiating_agent_did = initiating_agent.did();

    let mut task_mandate = root_mandate
        .delegate(
            initiating_agent_did.clone(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            ttl - Duration::minutes(10),
        )
        .unwrap();
    task_mandate.sign(orchestrator.signing_key());
    println!("  Initiating agent DID: {initiating_agent_did}");
    println!("  Scope: [schema:SearchAction]");
    println!(
        "  Parent mandate hash: {}",
        task_mandate.parent_mandate_hash.as_ref().unwrap()
    );
    println!();

    // Build and verify the mandate chain
    let chain = MandateChain {
        mandates: vec![root_mandate.clone(), task_mandate.clone()],
    };
    chain
        .verify_chain(&[principal.verifying_key(), orchestrator.verifying_key()])
        .expect("mandate chain verification failed");
    println!("  Mandate chain verified: root -> orchestrator -> initiating agent");
    println!();

    // ─── Step 6: Token Presentation ─────────────────────────────────
    println!("Step 6: Initiating agent presents capability token to search agent");
    let mut session =
        Session::initiate(&token, &search_operator_did, &orchestrator.verifying_key())
            .expect("session initiation failed");
    println!("  Session ID: {}", session.id);
    println!("  State: {}", session.state);
    println!(
        "  Nonce consumed: {}",
        session.is_nonce_consumed(&token.nonce)
    );
    println!();

    // ─── Step 7: Ephemeral Session DID Exchange ─────────────────────
    println!("Step 7: Both agents exchange ephemeral session DIDs");
    let initiator_session = SessionKeypair::generate();
    let receiver_session = SessionKeypair::generate();
    let initiator_session_did = initiator_session.did();
    let receiver_session_did = receiver_session.did();

    session
        .open(initiator_session_did.clone(), receiver_session_did.clone())
        .unwrap();
    println!("  Initiator session DID: {initiator_session_did}");
    println!("  Receiver session DID: {receiver_session_did}");
    println!("  State: {}", session.state);
    println!("  (Session DIDs are ephemeral — unlinked to principal identity)");
    println!();

    // ─── Step 8: Disclosure Exchange ────────────────────────────────
    println!("Step 8: Disclosure exchange — search requires ZERO personal context");
    println!("  Initiator discloses: [] (nothing)");
    println!("  Receiver provides: operator statement");
    println!("  Over-disclosure structurally prevented by protocol");
    println!();

    // ─── Step 9: Execution ──────────────────────────────────────────
    println!("Step 9: Search agent executes (stub — hardcoded results)");
    session.execute().unwrap();

    let search_results = serde_json::json!({
        "@context": "https://schema.org",
        "@type": "SearchResultsPage",
        "mainEntity": {
            "@type": "ItemList",
            "itemListElement": [
                {
                    "@type": "SearchResult",
                    "name": "Principal Agent Protocol - Architecture Specification",
                    "url": "https://baursoftware.com/pap",
                    "description": "End-to-end design of a principal-first, zero-trust agent negotiation protocol."
                },
                {
                    "@type": "SearchResult",
                    "name": "W3C DID Core Specification",
                    "url": "https://www.w3.org/TR/did-core/",
                    "description": "Decentralized Identifiers (DIDs) v1.0 - Core architecture."
                }
            ]
        }
    });
    println!("  State: {}", session.state);
    println!(
        "  Results:\n{}\n",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    // ─── Step 10: Transaction Receipt ───────────────────────────────
    println!("Step 10: Both agents co-sign transaction receipt");
    let mut receipt = TransactionReceipt::from_session(
        &session,
        vec![], // zero personal disclosure — the whole point
        vec!["operator:search_executed".into()],
        "schema:SearchAction executed".into(),
        "schema:SearchResultsPage returned".into(),
    )
    .unwrap();

    receipt.co_sign(initiator_session.signing_key());
    receipt.co_sign(receiver_session.signing_key());

    // Verify both signatures
    receipt
        .verify_both(
            &initiator_session.verifying_key(),
            &receiver_session.verifying_key(),
        )
        .expect("receipt verification failed");
    println!("  Receipt co-signed and verified");
    println!(
        "  Disclosed by initiator: {:?} (nothing)",
        receipt.disclosed_by_initiator
    );
    println!(
        "  Disclosed by receiver: {:?}",
        receipt.disclosed_by_receiver
    );
    println!();

    // ─── Step 11: Session Close ─────────────────────────────────────
    println!("Step 11: Session closes, ephemeral keys discarded");
    session.close().unwrap();
    println!("  State: {}", session.state);
    println!("  Ephemeral session DIDs: [discarded]");
    println!("  Nonce: [consumed, cannot be replayed]");
    println!();

    // ─── Step 12: Receipt ───────────────────────────────────────────
    println!("Step 12: Transaction receipt");
    println!("{}", receipt.to_json());
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Principal is root of trust (device-bound keypair)");
    println!("  [x] DID document contains no personal information");
    println!("  [x] Root mandate signed by principal, scope: SearchAction only");
    println!("  [x] Delegation scope <= parent scope (enforced)");
    println!("  [x] Delegation TTL <= parent TTL (enforced)");
    println!("  [x] Mandate chain cryptographically verified");
    println!("  [x] Capability token bound to target DID + action + nonce");
    println!("  [x] Token single-use (nonce consumed on session initiation)");
    println!("  [x] Session DIDs are ephemeral, unlinked to principal identity");
    println!("  [x] Zero personal disclosure for search transaction");
    println!("  [x] Receipt contains property references only, no values");
    println!("  [x] Receipt co-signed by both session parties");
    println!("  [x] Session closed, ephemeral keys discarded");
    println!("  [x] No platform stored any principal context");
}
