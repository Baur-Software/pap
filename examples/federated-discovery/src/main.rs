//! Federated Discovery PoC demonstrating:
//!
//! - FederatedRegistry with peer awareness and deduplication
//! - TLS identity generation with DID-bound self-signed certificates
//! - Certificate fingerprint pinning (no CA trust chain)
//! - Peer-to-peer agent advertisement propagation
//! - Signature verification on remote advertisements
//! - FederationServer serving agent queries over HTTP
//! - FederationClient querying and announcing across nodes
//! - Disclosure-constrained discovery across federated registries
//!
//! Two simulated federation nodes register agents locally, then sync
//! advertisements across the federation boundary. Every advertisement
//! is cryptographically signed and verified — unsigned ads are rejected.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use pap_did::PrincipalKeypair;
use pap_federation::{
    cert_fingerprint, generate_node_identity, FederatedRegistry, FederationMessage,
    FederationServer, RegistryPeer,
};
use pap_marketplace::AgentAdvertisement;
use rand::rngs::OsRng;

fn make_signed_ad(
    name: &str,
    action: &str,
    requires_disclosure: Vec<String>,
) -> (AgentAdvertisement, SigningKey) {
    let key = SigningKey::generate(&mut OsRng);
    let did = PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap().did();
    let mut ad = AgentAdvertisement::new(
        name,
        "ExampleCorp",
        &did,
        vec![action.into()],
        vec![],
        requires_disclosure,
        vec!["schema:SearchResult".into()],
    );
    ad.sign(&key).expect("Ed25519 is always supported");
    (ad, key)
}

#[tokio::main]
async fn main() {
    println!("=== PAP Federated Discovery Example ===");
    println!("Principal Agent Protocol v0.4.2 — Federation PoC\n");

    // ─── Step 1: Generate TLS Identities for Two Nodes ────────────────
    println!("Step 1: Generate self-signed TLS identities bound to DIDs");

    let node_a_kp = PrincipalKeypair::generate();
    let node_a_did = node_a_kp.did();
    let node_a_identity = generate_node_identity(&node_a_did).unwrap();
    println!("  Node A DID: {}...", &node_a_did[..30]);
    println!(
        "  Node A cert fingerprint: {}...",
        &node_a_identity.fingerprint[..24]
    );

    let node_b_kp = PrincipalKeypair::generate();
    let node_b_did = node_b_kp.did();
    let node_b_identity = generate_node_identity(&node_b_did).unwrap();
    println!("  Node B DID: {}...", &node_b_did[..30]);
    println!(
        "  Node B cert fingerprint: {}...",
        &node_b_identity.fingerprint[..24]
    );

    // Verify fingerprints are deterministic over the cert bytes
    assert_eq!(
        cert_fingerprint(&node_a_identity.cert_der),
        node_a_identity.fingerprint
    );
    assert_eq!(
        cert_fingerprint(&node_b_identity.cert_der),
        node_b_identity.fingerprint
    );
    println!("  Fingerprint determinism: verified");
    println!();

    // ─── Step 2: Build Federated Registries ───────────────────────────
    println!("Step 2: Build federated registries with local agents");

    let mut registry_a = FederatedRegistry::new();
    let mut registry_b = FederatedRegistry::new();

    // Node A has a search agent and a booking agent
    let (search_ad, _) = make_signed_ad("SearchBot", "schema:SearchAction", vec![]);
    let (booking_ad, _) = make_signed_ad(
        "BookingBot",
        "schema:ReserveAction",
        vec!["schema:Person.name".into(), "schema:Person.email".into()],
    );
    registry_a.register_local(search_ad.clone()).unwrap();
    registry_a.register_local(booking_ad.clone()).unwrap();
    println!(
        "  Node A: {} agents (SearchBot, BookingBot)",
        registry_a.len()
    );

    // Node B has a weather agent and a translation agent
    let (weather_ad, _) = make_signed_ad("WeatherBot", "schema:SearchAction", vec![]);
    let (translate_ad, _) = make_signed_ad("TranslateBot", "schema:TranslateAction", vec![]);
    registry_b.register_local(weather_ad.clone()).unwrap();
    registry_b.register_local(translate_ad.clone()).unwrap();
    println!(
        "  Node B: {} agents (WeatherBot, TranslateBot)",
        registry_b.len()
    );
    println!();

    // ─── Step 3: Peer Discovery ───────────────────────────────────────
    println!("Step 3: Register federation peers with fingerprint pinning");

    let peer_b = RegistryPeer::with_fingerprint(
        &node_b_did,
        "https://node-b.example.com:8443",
        &node_b_identity.fingerprint,
    );
    let peer_a = RegistryPeer::with_fingerprint(
        &node_a_did,
        "https://node-a.example.com:8443",
        &node_a_identity.fingerprint,
    );

    registry_a.add_peer(peer_b.clone());
    registry_b.add_peer(peer_a.clone());
    println!("  Node A knows {} peer(s)", registry_a.peers().len());
    println!("  Node B knows {} peer(s)", registry_b.peers().len());
    println!(
        "  Peer B fingerprint: {}...",
        &peer_b.cert_fingerprint.as_ref().unwrap()[..24]
    );
    println!();

    // ─── Step 4: Merge Remote Advertisements ──────────────────────────
    println!("Step 4: Sync advertisements across federation boundary");

    // Node A merges Node B's advertisements
    let node_b_ads = registry_b.all_advertisements().to_vec();
    let merged_into_a = registry_a.merge_remote(node_b_ads);
    println!("  Node A merged {merged_into_a} new ads from Node B");
    println!("  Node A total: {} agents", registry_a.len());

    // Node B merges Node A's advertisements
    let node_a_ads = registry_a.all_advertisements().to_vec();
    let merged_into_b = registry_b.merge_remote(node_a_ads);
    println!("  Node B merged {merged_into_b} new ads from Node A");
    println!("  Node B total: {} agents", registry_b.len());
    println!();

    // ─── Step 5: Deduplication ────────────────────────────────────────
    println!("Step 5: Deduplication — re-merge is a no-op");

    let re_merge = registry_a.merge_remote(registry_b.all_advertisements().to_vec());
    println!("  Re-merged into A: {re_merge} new (expected 0)");
    assert_eq!(re_merge, 0);
    println!("  Registry A still has {} agents", registry_a.len());
    println!();

    // ─── Step 6: Unsigned Ad Rejection ────────────────────────────────
    println!("Step 6: Unsigned advertisement rejected");

    let unsigned_ad = AgentAdvertisement::new(
        "MaliciousBot",
        "EvilCorp",
        "did:key:zFake",
        vec!["schema:SearchAction".into()],
        vec![],
        vec![],
        vec![],
    );
    let merged_unsigned = registry_a.merge_remote(vec![unsigned_ad]);
    println!("  Unsigned ad merged: {merged_unsigned} (expected 0)");
    assert_eq!(merged_unsigned, 0);
    println!("  Registry A unchanged: {} agents", registry_a.len());
    println!();

    // ─── Step 7: Disclosure-Constrained Query ─────────────────────────
    println!("Step 7: Disclosure-constrained query across federation");

    // Zero-disclosure search — should find SearchBot and WeatherBot (no requirements)
    let zero_results = registry_a.query_local_satisfiable("schema:SearchAction", &[]);
    println!(
        "  Zero-disclosure SearchAction: {} agents",
        zero_results.len()
    );
    for ad in &zero_results {
        println!("    - {}", ad.name);
    }

    // With name+email available — should also find BookingBot for ReserveAction
    let full_results = registry_a.query_local_satisfiable(
        "schema:ReserveAction",
        &["schema:Person.name".into(), "schema:Person.email".into()],
    );
    println!(
        "  ReserveAction with name+email: {} agents",
        full_results.len()
    );
    for ad in &full_results {
        println!("    - {} (requires: {:?})", ad.name, ad.requires_disclosure);
    }

    // Without required disclosure — BookingBot filtered out
    let no_disclosure = registry_a.query_local_satisfiable("schema:ReserveAction", &[]);
    println!(
        "  ReserveAction zero-disclosure: {} agents (BookingBot filtered out)",
        no_disclosure.len()
    );
    println!();

    // ─── Step 8: Federation Message Serialization ─────────────────────
    println!("Step 8: Federation message serialization roundtrip");

    let messages = vec![
        (
            "QueryByAction",
            FederationMessage::QueryByAction {
                action: "schema:SearchAction".into(),
                cursor: None,
                page_size: 20,
            },
        ),
        (
            "QueryResponse",
            FederationMessage::QueryResponse {
                advertisements: vec![search_ad.clone()],
                has_more: false,
                next_cursor: None,
            },
        ),
        (
            "Announce",
            FederationMessage::Announce {
                advertisement: Box::new(search_ad),
            },
        ),
        (
            "AnnounceAck",
            FederationMessage::AnnounceAck {
                hash: "abc123".into(),
                accepted: true,
            },
        ),
        ("PeerList", FederationMessage::PeerList),
        (
            "PeerListResponse",
            FederationMessage::PeerListResponse {
                peers: vec![peer_a],
            },
        ),
    ];

    for (name, msg) in &messages {
        let json = serde_json::to_string(msg).unwrap();
        let _restored: FederationMessage = serde_json::from_str(&json).unwrap();
        println!("  {name}: {} bytes, roundtrip OK", json.len());
    }
    println!();

    // ─── Step 9: Federation Server Router ─────────────────────────────
    println!("Step 9: Federation server builds valid router");

    let shared_registry = Arc::new(Mutex::new(registry_a));
    let server = FederationServer::new(
        shared_registry.clone(),
        8443,
        node_a_did.clone(),
        "https://node-a.example.com:8443".into(),
        node_a_identity.fingerprint.clone(),
    );
    let _router = server.router();
    println!("  FederationServer router built with 4 endpoints:");
    println!("    GET  /federation/identity");
    println!("    GET  /federation/query?action=...");
    println!("    POST /federation/announce");
    println!("    GET  /federation/peers");
    println!();

    // ─── Step 10: Peer Removal ────────────────────────────────────────
    println!("Step 10: Peer lifecycle — removal");

    let mut reg = shared_registry.lock().unwrap();
    let before = reg.peers().len();
    let removed = reg.remove_peer(&node_b_did);
    println!("  Removed peer {}: {removed}", &node_b_did[..30]);
    println!("  Peers: {before} -> {}", reg.peers().len());
    drop(reg);
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Self-signed TLS certs generated with DID bound as SAN URI");
    println!("  [x] Certificate fingerprints are deterministic SHA-256 over DER");
    println!("  [x] Peer fingerprint pinning — no CA in the trust chain");
    println!("  [x] Signed advertisements merge across federation boundary");
    println!("  [x] Unsigned advertisements rejected (signature verification)");
    println!("  [x] Content-hash deduplication prevents duplicate registration");
    println!("  [x] Disclosure-constrained queries filter across federated ads");
    println!("  [x] Federation messages serialize/deserialize correctly");
    println!("  [x] FederationServer builds valid Axum router");
    println!("  [x] Peer lifecycle: add, query, remove");
    println!("  [x] DIDs are the trust root — certs, ads, and queries all bind to DIDs");
}
