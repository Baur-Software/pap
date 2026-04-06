#![allow(clippy::unwrap_used)]
use criterion::{criterion_group, criterion_main, Criterion};

use chrono::{Duration, Utc};
use std::collections::HashMap;

use pap_core::mandate::{Mandate, MandateChain};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_credential::SelectiveDisclosureJwt;
use pap_did::PrincipalKeypair;
use pap_federation::{FederatedRegistry, FederationMessage, RegistryPeer};
use pap_marketplace::AgentAdvertisement;
use pap_test_utils::{did_from_key, make_keypair};

// ---------------------------------------------------------------------------
// 1. Ed25519 keypair generation
// ---------------------------------------------------------------------------
fn bench_keypair_generation(c: &mut Criterion) {
    c.bench_function("ed25519_keypair_generation", |b| {
        b.iter(PrincipalKeypair::generate);
    });
}

// ---------------------------------------------------------------------------
// 2. did:key derivation
// ---------------------------------------------------------------------------
fn bench_did_key_derivation(c: &mut Criterion) {
    let key = make_keypair();
    let vk = key.verifying_key();

    c.bench_function("did_key_derivation", |b| {
        b.iter(|| pap_did::public_key_to_did(&vk));
    });
}

// ---------------------------------------------------------------------------
// 3. Mandate creation + sign
// ---------------------------------------------------------------------------
fn bench_mandate_create_sign(c: &mut Criterion) {
    let principal_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let ttl = Utc::now() + Duration::hours(1);

    c.bench_function("mandate_create_sign", |b| {
        b.iter(|| {
            let mut mandate = Mandate::issue_root(
                principal_did.clone(),
                "did:key:zagent".into(),
                Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
                DisclosureSet::empty(),
                ttl,
            );
            mandate
                .sign(&principal_key)
                .expect("Ed25519 is always supported");
            mandate
        });
    });
}

// ---------------------------------------------------------------------------
// 4. Mandate chain verification (depth 3)
// ---------------------------------------------------------------------------
fn bench_mandate_chain_verify(c: &mut Criterion) {
    let principal_key = make_keypair();
    let agent1_key = make_keypair();
    let agent2_key = make_keypair();
    let principal_did = did_from_key(&principal_key);
    let agent1_did = did_from_key(&agent1_key);
    let agent2_did = did_from_key(&agent2_key);
    let ttl = Utc::now() + Duration::hours(1);

    let scope = Scope::new(vec![
        ScopeAction::new("schema:SearchAction"),
        ScopeAction::new("schema:ReserveAction"),
    ]);

    // Root mandate: principal -> agent1
    let mut root = Mandate::issue_root(
        principal_did,
        agent1_did,
        scope.clone(),
        DisclosureSet::empty(),
        ttl,
    );
    root.sign(&principal_key)
        .expect("Ed25519 is always supported");

    // Depth 1: agent1 -> agent2
    let mut child1 = root
        .delegate(
            agent2_did,
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            ttl - Duration::minutes(10),
        )
        .unwrap();
    child1
        .sign(&agent1_key)
        .expect("Ed25519 is always supported");

    // Depth 2: agent2 -> leaf
    let mut child2 = child1
        .delegate(
            "did:key:zleaf".into(),
            Scope::new(vec![ScopeAction::new("schema:SearchAction")]),
            DisclosureSet::empty(),
            ttl - Duration::minutes(20),
        )
        .unwrap();
    child2
        .sign(&agent2_key)
        .expect("Ed25519 is always supported");

    let chain = MandateChain {
        mandates: vec![root, child1, child2],
    };
    let keys = [
        principal_key.verifying_key(),
        agent1_key.verifying_key(),
        agent2_key.verifying_key(),
    ];

    c.bench_function("mandate_chain_verify_depth3", |b| {
        b.iter(|| chain.verify_chain(&keys).unwrap());
    });
}

// ---------------------------------------------------------------------------
// 5. SD-JWT issue (5 claims)
// ---------------------------------------------------------------------------
fn bench_sd_jwt_issue(c: &mut Criterion) {
    let key = make_keypair();
    let did = did_from_key(&key);

    c.bench_function("sd_jwt_issue_5claims", |b| {
        b.iter(|| {
            let mut claims = HashMap::new();
            claims.insert("schema:name".into(), serde_json::json!("Alice"));
            claims.insert(
                "schema:email".into(),
                serde_json::json!("alice@example.com"),
            );
            claims.insert("schema:nationality".into(), serde_json::json!("Wonderland"));
            claims.insert("schema:birthDate".into(), serde_json::json!("1990-01-01"));
            claims.insert("schema:telephone".into(), serde_json::json!("+1-555-0100"));

            let mut sd_jwt = SelectiveDisclosureJwt::new(did.clone(), claims);
            sd_jwt.sign(&key).expect("Ed25519 is always supported");
            sd_jwt
        });
    });
}

// ---------------------------------------------------------------------------
// 6. SD-JWT verify + selective disclose (5 claims, 3 disclosed)
// ---------------------------------------------------------------------------
fn bench_sd_jwt_verify_disclose(c: &mut Criterion) {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut claims = HashMap::new();
    claims.insert("schema:name".into(), serde_json::json!("Alice"));
    claims.insert(
        "schema:email".into(),
        serde_json::json!("alice@example.com"),
    );
    claims.insert("schema:nationality".into(), serde_json::json!("Wonderland"));
    claims.insert("schema:birthDate".into(), serde_json::json!("1990-01-01"));
    claims.insert("schema:telephone".into(), serde_json::json!("+1-555-0100"));

    let mut sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    sd_jwt.sign(&key).expect("Ed25519 is always supported");
    let vk = key.verifying_key();

    c.bench_function("sd_jwt_verify_disclose_3of5", |b| {
        b.iter(|| {
            let disclosures = sd_jwt
                .disclose(&["schema:name", "schema:email", "schema:nationality"])
                .unwrap();
            sd_jwt.verify_disclosures(&disclosures, &vk).unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// 7. Session open (full lifecycle, loopback)
// ---------------------------------------------------------------------------
fn bench_session_open(c: &mut Criterion) {
    let issuer_key = make_keypair();
    let issuer_did = did_from_key(&issuer_key);
    let target_did = did_from_key(&make_keypair());
    let ttl = Utc::now() + Duration::hours(1);

    c.bench_function("session_open_full_lifecycle", |b| {
        b.iter(|| {
            // Phase 1: Token presentation
            let mut token = CapabilityToken::mint(
                target_did.clone(),
                "schema:SearchAction".into(),
                issuer_did.clone(),
                ttl,
            );
            token
                .sign(&issuer_key)
                .expect("Ed25519 is always supported");

            // Phase 2: Session initiation + token verification
            let mut session =
                Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();

            // Phase 3: DID exchange
            let init_session = pap_did::SessionKeypair::generate();
            let recv_session = pap_did::SessionKeypair::generate();
            session
                .open(init_session.did(), recv_session.did())
                .unwrap();

            // Phase 4: Execution
            session.execute().unwrap();

            // Phase 5: Close
            session.close().unwrap();
        });
    });
}

// ---------------------------------------------------------------------------
// 8. Receipt creation + co-sign
// ---------------------------------------------------------------------------
fn bench_receipt_cosign(c: &mut Criterion) {
    // Pre-build an executed session
    let issuer_key = make_keypair();
    let issuer_did = did_from_key(&issuer_key);
    let target_did = did_from_key(&make_keypair());
    let ttl = Utc::now() + Duration::hours(1);

    let mut token = CapabilityToken::mint(
        target_did.clone(),
        "schema:SearchAction".into(),
        issuer_did,
        ttl,
    );
    token
        .sign(&issuer_key)
        .expect("Ed25519 is always supported");

    let mut session = Session::initiate(&token, &target_did, &issuer_key.verifying_key()).unwrap();
    session
        .open("did:key:zinit_sess".into(), "did:key:zrecv_sess".into())
        .unwrap();
    session.execute().unwrap();

    let init_session_key = make_keypair();
    let recv_session_key = make_keypair();

    c.bench_function("receipt_create_cosign", |b| {
        b.iter(|| {
            let mut receipt = TransactionReceipt::from_session(
                &session,
                vec!["schema:Person.name".into()],
                vec!["operator:search_executed".into()],
                "schema:SearchAction executed".into(),
                "schema:SearchResult returned".into(),
            )
            .unwrap();
            receipt.co_sign(&init_session_key);
            receipt.co_sign(&recv_session_key);
            receipt
        });
    });
}

// ---------------------------------------------------------------------------
// 9. Federation announce (single peer, local processing)
// ---------------------------------------------------------------------------
fn bench_federation_announce(c: &mut Criterion) {
    c.bench_function("federation_announce_local", |b| {
        b.iter_batched(
            || {
                // Setup: fresh registry + fresh signed advertisement per iteration
                let mut registry = FederatedRegistry::new();
                registry.add_peer(RegistryPeer::new("did:key:zPeer1", "http://peer1:8080"));

                let key = make_keypair();
                let did = did_from_key(&key);
                let mut ad = AgentAdvertisement::new(
                    "Search Agent",
                    "TestCorp",
                    &did,
                    vec!["schema:SearchAction".into()],
                    vec!["schema:WebPage".into()],
                    vec![],
                    vec!["schema:SearchResult".into()],
                );
                ad.sign(&key).expect("Ed25519 is always supported");

                // Build the announce message (simulating what arrives over the wire)
                let msg = FederationMessage::Announce {
                    advertisement: Box::new(ad),
                };
                let wire_bytes = serde_json::to_vec(&msg).unwrap();

                (registry, wire_bytes)
            },
            |(mut registry, wire_bytes)| {
                // Benchmark: deserialize + verify + merge (the server-side announce path)
                let msg: FederationMessage = serde_json::from_slice(&wire_bytes).unwrap();
                if let FederationMessage::Announce { advertisement } = msg {
                    let hash = advertisement.hash();
                    let accepted = registry.merge_remote(vec![*advertisement]) > 0;
                    FederationMessage::AnnounceAck { hash, accepted }
                } else {
                    unreachable!()
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_keypair_generation,
    bench_did_key_derivation,
    bench_mandate_create_sign,
    bench_mandate_chain_verify,
    bench_sd_jwt_issue,
    bench_sd_jwt_verify_disclose,
    bench_session_open,
    bench_receipt_cosign,
    bench_federation_announce,
);
criterion_main!(benches);
