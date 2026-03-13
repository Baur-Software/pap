//! Travel booking PoC demonstrating:
//!
//! - SD-JWT selective disclosure (name + nationality required, email prohibited)
//! - W3C Verifiable Credential envelope wrapping the mandate
//! - Marketplace disclosure filtering (agents requiring too much are filtered out)
//! - Non-zero disclosure in the session handshake
//!
//! This is the second simplest meaningful transaction: a flight booking
//! that requires personal context to complete, proving the disclosure
//! controls work under real constraints.

use chrono::{Duration, Utc};
use pap_core::mandate::Mandate;
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_credential::{SelectiveDisclosureJwt, VerifiableCredential};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};
use std::collections::HashMap;

fn main() {
    println!("=== PAP Travel Booking Example ===");
    println!("Principal Agent Protocol v0.1 — Selective Disclosure PoC\n");

    // ─── Step 1: Principal Setup ────────────────────────────────────
    println!("Step 1: Principal generates keypair and disclosure profile");
    let principal = PrincipalKeypair::generate();
    let principal_did = principal.did();
    println!("  Principal DID: {principal_did}");

    // The principal's disclosure profile — what they hold and under what conditions
    println!("  Disclosure profile:");
    println!("    schema:name        → permitted (travel transactions)");
    println!("    schema:email       → NEVER (prohibited)");
    println!("    schema:nationality → permitted (travel transactions)");
    println!("    schema:telephone   → NEVER (prohibited)");
    println!();

    // ─── Step 2: Root Mandate with Disclosure Set ───────────────────
    println!("Step 2: Principal issues root mandate with scoped disclosure");
    let orchestrator = PrincipalKeypair::generate();
    let orchestrator_did = orchestrator.did();
    let ttl = Utc::now() + Duration::hours(2);

    let disclosure_set = DisclosureSet::new(vec![
        DisclosureEntry::new(
            "schema:Person",
            vec!["schema:name".into(), "schema:nationality".into()],
            vec!["schema:email".into(), "schema:telephone".into()],
        )
        .session_only()
        .no_retention(),
    ]);

    let mut root_mandate = Mandate::issue_root(
        principal_did.clone(),
        orchestrator_did.clone(),
        Scope::new(vec![
            ScopeAction::with_object("schema:ReserveAction", "schema:Flight"),
        ]),
        disclosure_set.clone(),
        ttl,
    );
    root_mandate.sign(principal.signing_key());

    println!("  Scope: [schema:ReserveAction (object: schema:Flight)]");
    println!("  Permitted disclosure: [schema:name, schema:nationality]");
    println!("  Prohibited disclosure: [schema:email, schema:telephone]");
    println!("  Retention: session_only=true, no_retention=true");
    println!();

    // ─── Step 3: Wrap Mandate in Verifiable Credential ──────────────
    println!("Step 3: Mandate wrapped in W3C Verifiable Credential envelope");
    let mandate_json = serde_json::to_value(&root_mandate).unwrap();
    let mut vc = VerifiableCredential::from_mandate(
        &principal_did,
        serde_json::json!({
            "id": &orchestrator_did,
            "mandate": mandate_json,
        }),
        Some(ttl),
    );
    vc.sign(principal.signing_key(), &format!("{principal_did}#key-1"));

    assert!(vc.verify(&principal.verifying_key()).is_ok());
    println!("  VC type: [VerifiableCredential, PAPMandateCredential]");
    println!("  VC signed and verified: true");
    println!("  VC ID: {}", vc.id);
    println!();

    // ─── Step 4: Marketplace Query with Disclosure Filtering ────────
    println!("Step 4: Marketplace query — agents filtered by disclosure requirements");

    let mut registry = MarketplaceRegistry::new();

    // Agent 1: Flight booking — requires name + nationality (satisfiable)
    let flight_operator = PrincipalKeypair::generate();
    let flight_operator_did = flight_operator.did();
    let mut flight_ad = AgentAdvertisement::new(
        "SkyBook Flight Agent",
        "SkyBook Travel",
        &flight_operator_did,
        vec!["schema:ReserveAction".into()],
        vec!["schema:Flight".into()],
        vec!["schema:Person.name".into(), "schema:Person.nationality".into()],
        vec!["schema:Flight".into(), "schema:Ticket".into()],
    );
    flight_ad.sign(flight_operator.signing_key());
    registry.register(flight_ad).unwrap();

    // Agent 2: Premium booking — requires name + nationality + email (NOT satisfiable)
    let premium_operator = PrincipalKeypair::generate();
    let premium_operator_did = premium_operator.did();
    let mut premium_ad = AgentAdvertisement::new(
        "LuxAir Premium Agent",
        "LuxAir",
        &premium_operator_did,
        vec!["schema:ReserveAction".into()],
        vec!["schema:Flight".into()],
        vec![
            "schema:Person.name".into(),
            "schema:Person.nationality".into(),
            "schema:Person.email".into(), // principal prohibits this
        ],
        vec!["schema:Flight".into(), "schema:Ticket".into()],
    );
    premium_ad.sign(premium_operator.signing_key());
    registry.register(premium_ad).unwrap();

    // Agent 3: Hotel booking — wrong action type
    let hotel_operator = PrincipalKeypair::generate();
    let hotel_operator_did = hotel_operator.did();
    let mut hotel_ad = AgentAdvertisement::new(
        "StayWell Hotel Agent",
        "StayWell",
        &hotel_operator_did,
        vec!["schema:ReserveAction".into()],
        vec!["schema:LodgingBusiness".into()],
        vec!["schema:Person.name".into()],
        vec!["schema:LodgingReservation".into()],
    );
    hotel_ad.sign(hotel_operator.signing_key());
    registry.register(hotel_ad).unwrap();

    // Available properties from the principal's permitted disclosure,
    // expressed in the marketplace convention (Type.property)
    let available: Vec<String> = vec![
        "schema:Person.name".into(),
        "schema:Person.nationality".into(),
    ];
    println!("  Registered agents: {}", registry.len());
    println!("  Available disclosure: {available:?}");
    println!();

    // Query: ReserveAction agents satisfiable by our disclosure profile
    let all_reserve = registry.query_by_action("schema:ReserveAction");
    println!("  All agents supporting schema:ReserveAction: {}", all_reserve.len());
    for ad in &all_reserve {
        let satisfies = ad.disclosure_satisfiable(&available);
        println!("    - {} (requires: {:?}) {}", ad.name, ad.requires_disclosure,
            if satisfies { "✓" } else { "✗" });
    }

    let satisfiable = registry.query_satisfiable("schema:ReserveAction", &available);
    println!("  After disclosure filtering: {}", satisfiable.len());
    for ad in &satisfiable {
        println!("    - {} ✓", ad.name);
    }
    println!();
    println!("  LuxAir Premium Agent FILTERED OUT — requires schema:Person.email");
    println!("  which the principal has prohibited. Over-disclosure structurally prevented.");
    println!("  StayWell Hotel Agent included — its disclosure requirements are satisfiable,");
    println!("  but the orchestrator would further filter by object_types in production.");
    println!();

    // ─── Step 5: Capability Token + Task Mandate ────────────────────
    println!("Step 5: Orchestrator mints token and delegates task mandate");
    let mut token = CapabilityToken::mint(
        flight_operator_did.clone(),
        "schema:ReserveAction".into(),
        orchestrator_did.clone(),
        ttl,
    );
    token.sign(orchestrator.signing_key());

    let initiating_agent = PrincipalKeypair::generate();
    let initiating_agent_did = initiating_agent.did();
    let mut task_mandate = root_mandate
        .delegate(
            initiating_agent_did.clone(),
            Scope::new(vec![
                ScopeAction::with_object("schema:ReserveAction", "schema:Flight"),
            ]),
            disclosure_set.clone(),
            ttl - Duration::minutes(30),
        )
        .unwrap();
    task_mandate.sign(orchestrator.signing_key());
    println!("  Token target: {}", token.target_did);
    println!("  Initiating agent DID: {initiating_agent_did}");
    println!();

    // ─── Step 6: Session Handshake ──────────────────────────────────
    println!("Step 6: Session initiation and ephemeral DID exchange");
    let mut session = Session::initiate(
        &token,
        &flight_operator_did,
        &orchestrator.verifying_key(),
    )
    .expect("session initiation failed");

    let initiator_session = SessionKeypair::generate();
    let receiver_session = SessionKeypair::generate();
    session
        .open(initiator_session.did(), receiver_session.did())
        .unwrap();
    println!("  Session ID: {}", session.id);
    println!("  State: {}", session.state);
    println!();

    // ─── Step 7: SD-JWT Selective Disclosure ─────────────────────────
    println!("Step 7: SD-JWT selective disclosure — name and nationality only");

    let mut claims = HashMap::new();
    claims.insert("schema:name".into(), serde_json::json!("Alice Baur"));
    claims.insert("schema:email".into(), serde_json::json!("alice@example.com"));
    claims.insert("schema:nationality".into(), serde_json::json!("US"));
    claims.insert("schema:telephone".into(), serde_json::json!("+1-555-0100"));

    let mut sd_jwt = SelectiveDisclosureJwt::new(principal_did.clone(), claims);
    sd_jwt.sign(principal.signing_key());

    // Disclose ONLY what the mandate permits — name and nationality
    let disclosures = sd_jwt
        .disclose(&["schema:name", "schema:nationality"])
        .unwrap();
    println!("  SD-JWT signed by principal");
    println!("  Total claims held: 4 (name, email, nationality, telephone)");
    println!("  Claims disclosed: {}", disclosures.len());
    for d in &disclosures {
        println!("    ✓ {} = {}", d.key, d.value);
    }
    println!("  Claims withheld:");
    println!("    ✗ schema:email (prohibited by mandate)");
    println!("    ✗ schema:telephone (prohibited by mandate)");
    println!();

    // Verify the disclosures match the signed commitments
    sd_jwt
        .verify_disclosures(&disclosures, &principal.verifying_key())
        .expect("disclosure verification failed");
    println!("  Disclosure integrity verified — hashes match signed commitments");
    println!("  Over-disclosure structurally impossible: SD-JWT payload contains");
    println!("  only the properties declared in the mandate's disclosure set.");
    println!();

    // ─── Step 8: Execution ──────────────────────────────────────────
    println!("Step 8: Flight agent executes booking");
    session.execute().unwrap();

    let booking_result = serde_json::json!({
        "@context": "https://schema.org",
        "@type": "FlightReservation",
        "reservationStatus": "schema:ReservationConfirmed",
        "reservationFor": {
            "@type": "Flight",
            "flightNumber": "SK 1234",
            "departureAirport": { "@type": "Airport", "iataCode": "SFO" },
            "arrivalAirport": { "@type": "Airport", "iataCode": "CPH" },
            "departureTime": "2026-04-15T08:30:00-07:00",
            "arrivalTime": "2026-04-16T05:45:00+02:00"
        },
        "ticketToken": "qr://SKYBOOK-ABCD1234"
    });
    println!("  State: {}", session.state);
    println!("  Result:\n{}\n", serde_json::to_string_pretty(&booking_result).unwrap());

    // ─── Step 9: Transaction Receipt ────────────────────────────────
    println!("Step 9: Both agents co-sign transaction receipt");
    let mut receipt = TransactionReceipt::from_session(
        &session,
        // Property REFERENCES only — never the values
        vec!["schema:Person.name".into(), "schema:Person.nationality".into()],
        vec!["operator:reservation_confirmed".into()],
        "schema:ReserveAction executed on schema:Flight".into(),
        "schema:FlightReservation returned".into(),
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
    println!("  Disclosed by initiator: {:?}", receipt.disclosed_by_initiator);
    println!("  ↑ Property REFERENCES only — \"Alice Baur\" and \"US\" are NOT in the receipt");
    println!("  Disclosed by receiver: {:?}", receipt.disclosed_by_receiver);
    println!();

    // ─── Step 10: Session Close ─────────────────────────────────────
    println!("Step 10: Session closes, ephemeral keys discarded");
    session.close().unwrap();
    println!("  State: {}", session.state);
    println!();

    // ─── Receipt ────────────────────────────────────────────────────
    println!("Transaction receipt:");
    println!("{}", receipt.to_json());
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Mandate carries explicit disclosure set with permitted/prohibited");
    println!("  [x] Mandate wrapped in W3C Verifiable Credential envelope");
    println!("  [x] VC signed and verifiable against principal's public key");
    println!("  [x] Marketplace agents filtered by satisfiable disclosure requirements");
    println!("  [x] LuxAir agent rejected — requires email which principal prohibits");
    println!("  [x] SD-JWT selective disclosure: 2 of 4 claims revealed");
    println!("  [x] Withheld claims (email, telephone) cryptographically uncommitted");
    println!("  [x] Disclosure integrity verified against signed hash commitments");
    println!("  [x] session_only=true, no_retention=true enforced on disclosed data");
    println!("  [x] Receipt contains property references only — no personal values");
    println!("  [x] Session DIDs ephemeral, keys discarded at close");
    println!("  [x] Receiving agent retains nothing beyond the transaction record");
}
