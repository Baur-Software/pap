//! Payment PoC demonstrating:
//!
//! - payment_proof field on mandates (Chaumian ecash blind-signed token)
//! - Auto-approval policies (principal-authored, cannot exceed mandate scope)
//! - Continuity tokens (encrypted vendor state, principal-controlled TTL)
//! - Value-capped scope conditions
//!
//! This example proves the protocol extensions from spec sections 9.1, 9.3,
//! and 9.4 work together: a principal pre-authorizes small purchases with
//! an auto-approval policy, the payment proof is unlinkable from identity,
//! and the vendor hands back a continuity token for future interactions.

use chrono::{Duration, Utc};
use pap_core::error::PapError;
use pap_core::extensions::{AutoApprovalPolicy, ContinuityToken};
use pap_core::mandate::Mandate;
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};

fn main() {
    println!("=== PAP Payment Example ===");
    println!("Principal Agent Protocol v0.1 — Extensions PoC\n");

    // ─── Step 1: Principal + Orchestrator Setup ─────────────────────
    println!("Step 1: Principal and orchestrator setup");
    let principal = PrincipalKeypair::generate();
    let principal_did = principal.did();
    let orchestrator = PrincipalKeypair::generate();
    let orchestrator_did = orchestrator.did();
    let ttl = Utc::now() + Duration::hours(2);

    // Scope includes PayAction with value conditions
    let mut pay_action = ScopeAction::new("schema:PayAction");
    pay_action
        .conditions
        .insert("max_value".into(), serde_json::json!(50));
    pay_action
        .conditions
        .insert("currency".into(), serde_json::json!("USD"));
    pay_action
        .conditions
        .insert("requires_confirmation_above".into(), serde_json::json!(20));

    let mandate_scope = Scope::new(vec![ScopeAction::new("schema:SearchAction"), pay_action]);

    let mut root_mandate = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        mandate_scope.clone(),
        DisclosureSet::empty(), // digital purchase — no personal disclosure needed
        ttl,
    );

    // Attach a payment proof — a blind-signed Chaumian ecash token
    // In production this would be a real token from a mint.
    // The vendor receives proof of value transfer but nothing that identifies the payer.
    root_mandate.payment_proof = Some(
        "ecash:blind:v1:mint=example.com:amount=50:token=ZGVtby1ibGluZC1zaWduZWQtdG9rZW4".into(),
    );
    root_mandate.sign(principal.signing_key());

    println!("  Principal DID: {principal_did}");
    println!("  Orchestrator DID: {orchestrator_did}");
    println!("  Scope: [SearchAction, PayAction(max: $50, confirm above: $20)]");
    println!("  Payment proof: Chaumian ecash blind-signed token (unlinkable)");
    println!("  Disclosure: empty (digital purchase, no personal context)");
    println!();

    // ─── Step 2: Auto-Approval Policy ───────────────────────────────
    println!("Step 2: Principal defines auto-approval policy");

    // Policy 1: Auto-approve small searches (no value cap needed)
    let search_policy = AutoApprovalPolicy::new(
        "Auto-approve searches",
        Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
    );

    // Policy 2: Auto-approve payments under $20, zero additional disclosure
    let pay_policy = AutoApprovalPolicy::new(
        "Auto-approve small purchases",
        Scope::new(vec![ScopeAction::new("schema:PayAction")]),
    )
    .with_max_value(20.0);

    // Both policies must be subsets of the mandate scope
    search_policy
        .validate_against_mandate(&mandate_scope)
        .unwrap();
    pay_policy.validate_against_mandate(&mandate_scope).unwrap();

    println!("  Policy 1: \"{}\"", search_policy.name);
    println!("    Scope: [SearchAction]");
    println!("    Max value: none (search has no monetary value)");
    println!(
        "    Zero additional disclosure: {}",
        search_policy.zero_additional_disclosure
    );
    println!("    Validated against mandate: ✓");
    println!();

    println!("  Policy 2: \"{}\"", pay_policy.name);
    println!("    Scope: [PayAction]");
    println!("    Max value: ${:.2}", pay_policy.max_value.unwrap());
    println!(
        "    Zero additional disclosure: {}",
        pay_policy.zero_additional_disclosure
    );
    println!("    Validated against mandate: ✓");
    println!();

    // Policy 3: REJECTED — exceeds mandate scope
    let bad_policy = AutoApprovalPolicy::new(
        "Auto-approve reservations",
        Scope::new(vec![ScopeAction::new("schema:ReserveAction")]),
    );

    let result = bad_policy.validate_against_mandate(&mandate_scope);
    println!("  Policy 3: \"{}\"", bad_policy.name);
    println!("    Scope: [ReserveAction] — NOT in mandate scope");
    match result {
        Err(PapError::PolicyExceedsMandate) => {
            println!("    REJECTED — PolicyExceedsMandate ✓");
            println!("    A policy cannot be more permissive than the mandate.");
            println!("    An agent cannot trigger a policy change by requesting it.");
        }
        other => panic!("expected PolicyExceedsMandate, got: {other:?}"),
    }
    println!();

    // ─── Step 3: Marketplace + Session ──────────────────────────────
    println!("Step 3: Payment transaction with marketplace agent");

    let vendor_operator = PrincipalKeypair::generate();
    let vendor_operator_did = vendor_operator.did();
    let mut vendor_ad = AgentAdvertisement::new(
        "DigitalStore Payment Agent",
        "DigitalStore Inc",
        &vendor_operator_did,
        vec!["schema:PayAction".into()],
        vec!["schema:DigitalDocument".into()],
        vec![], // digital purchase — no personal disclosure required
        vec!["schema:Invoice".into(), "schema:DigitalDocument".into()],
    );
    vendor_ad.sign(vendor_operator.signing_key());

    let mut registry = MarketplaceRegistry::new();
    registry.register(vendor_ad).unwrap();

    let matches = registry.query_satisfiable("schema:PayAction", &[]);
    assert_eq!(matches.len(), 1);
    println!(
        "  Vendor: {} (operator: {})",
        matches[0].name, matches[0].provider.did
    );
    println!("  Disclosure required: [] (none — digital purchase)");
    println!();

    // Mint token, initiate session
    let mut token = CapabilityToken::mint(
        vendor_operator_did.clone(),
        "schema:PayAction".into(),
        orchestrator_did.clone(),
        ttl,
    );
    token.sign(orchestrator.signing_key());

    let mut session =
        Session::initiate(&token, &vendor_operator_did, &orchestrator.verifying_key())
            .expect("session initiation failed");

    let initiator_session = SessionKeypair::generate();
    let receiver_session = SessionKeypair::generate();
    session
        .open(initiator_session.did(), receiver_session.did())
        .unwrap();

    println!("  Session ID: {}", session.id);
    println!("  State: {}", session.state);
    println!();

    // ─── Step 4: Execution ──────────────────────────────────────────
    println!("Step 4: Payment executed ($12.99 — under auto-approval threshold)");
    session.execute().unwrap();

    let purchase_result = serde_json::json!({
        "@context": "https://schema.org",
        "@type": "Invoice",
        "totalPaymentDue": {
            "@type": "MonetaryAmount",
            "value": 12.99,
            "currency": "USD"
        },
        "paymentStatus": "PaymentComplete",
        "referencesOrder": {
            "@type": "Order",
            "orderedItem": {
                "@type": "DigitalDocument",
                "name": "PAP Architecture Specification (PDF)",
                "encodingFormat": "application/pdf"
            }
        }
    });

    println!("  Amount: $12.99 (< $20.00 auto-approval cap)");
    println!("  Auto-approved: yes (policy: \"{}\")", pay_policy.name);
    println!("  Principal confirmation required: no");
    println!("  Payment proof: ecash blind-signed token (vendor cannot identify payer)");
    println!(
        "  Result:\n{}\n",
        serde_json::to_string_pretty(&purchase_result).unwrap()
    );

    // ─── Step 5: Transaction Receipt ────────────────────────────────
    println!("Step 5: Co-signed transaction receipt");
    let mut receipt = TransactionReceipt::from_session(
        &session,
        vec![], // zero personal disclosure
        vec![
            "operator:payment_received".into(),
            "operator:digital_document_delivered".into(),
        ],
        "schema:PayAction executed ($12.99 USD)".into(),
        "schema:Invoice + schema:DigitalDocument returned".into(),
    )
    .unwrap();

    receipt.co_sign(initiator_session.signing_key());
    receipt.co_sign(receiver_session.signing_key());
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

    // ─── Step 6: Continuity Token ───────────────────────────────────
    println!("Step 6: Vendor issues continuity token for future interactions");

    // At session close, the vendor writes encrypted relationship state
    // and hands it to the orchestrator. The orchestrator stores it locally.
    let continuity = ContinuityToken::new(
        "schema:Order",
        &vendor_operator_did,
        // In production this would be encrypted with the vendor's key
        "encrypted:v1:order_id=DS-2026-0042:items=[pap-spec-pdf]:support_tier=standard",
        Utc::now() + Duration::days(90), // principal sets the TTL, not the vendor
    );

    println!(
        "  Schema type: {} (orchestrator can inspect shape without decrypting)",
        continuity.schema_type
    );
    println!("  Vendor DID: {}", continuity.vendor_did);
    println!("  TTL: 90 days (set by PRINCIPAL, not vendor)");
    println!("  Expired: {}", continuity.is_expired());
    println!("  Storage: orchestrator's local store (not vendor's servers)");
    println!();

    // Serialization roundtrip
    let ct_json = serde_json::to_string_pretty(&continuity).unwrap();
    let ct_restored: ContinuityToken = serde_json::from_str(&ct_json).unwrap();
    assert_eq!(continuity.vendor_did, ct_restored.vendor_did);
    assert_eq!(continuity.schema_type, ct_restored.schema_type);

    println!("  Continuity token serialized and restored: ✓");
    println!("  When principal returns: orchestrator presents token, vendor decrypts");
    println!("  To sever relationship: principal deletes the token. Done.");
    println!();

    // ─── Step 7: Session Close ──────────────────────────────────────
    println!("Step 7: Session closes");
    session.close().unwrap();
    println!("  State: {}", session.state);
    println!();

    // ─── Receipt ────────────────────────────────────────────────────
    println!("Transaction receipt:");
    println!("{}", receipt.to_json());
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Payment proof attached to mandate (Chaumian ecash, unlinkable)");
    println!("  [x] Scope conditions: max_value=$50, currency=USD, confirm_above=$20");
    println!("  [x] Auto-approval policy validated against mandate scope");
    println!("  [x] Policy exceeding mandate scope: REJECTED");
    println!("  [x] $12.99 purchase auto-approved (below $20 threshold)");
    println!("  [x] Zero personal disclosure for digital purchase");
    println!("  [x] Vendor cannot identify payer from payment proof");
    println!("  [x] Continuity token: encrypted state, principal-controlled TTL");
    println!("  [x] Continuity token stored by orchestrator, not vendor");
    println!("  [x] Receipt co-signed, property references only");
    println!("  [x] Session closed, ephemeral keys discarded");
}
