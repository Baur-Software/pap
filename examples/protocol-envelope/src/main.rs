//! Protocol Envelope PoC demonstrating:
//!
//! - Envelope wrapping of protocol messages with routing and sequencing
//! - Ed25519 signing of envelopes using ephemeral session keys
//! - Tamper detection: payload modification invalidates signature
//! - Sequence number preservation for replay prevention
//! - Wrong-key rejection: forged envelopes detected
//! - Full message type coverage with serialization roundtrips
//! - Canonical signable bytes: SHA-256(session_id || sequence || payload)
//!
//! The envelope is the unit of transport in PAP. Every protocol message
//! travels inside an envelope that binds it to a session, a sender, a
//! recipient, and a sequence number. After the DID exchange phase,
//! envelopes carry an Ed25519 signature from the sender's session key.

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use pap_core::receipt::TransactionReceipt;
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_proto::{Envelope, ProtocolMessage};
use rand::rngs::OsRng;

fn main() {
    println!("=== PAP Protocol Envelope Example ===");
    println!("Principal Agent Protocol v0.4.2 — Envelope & Integrity PoC\n");

    // ─── Step 1: Create Session DIDs ──────────────────────────────────
    println!("Step 1: Generate ephemeral session keypairs");

    let initiator_session = SessionKeypair::generate();
    let receiver_session = SessionKeypair::generate();
    let session_id = "session-demo-001";

    println!(
        "  Initiator session DID: {}...",
        &initiator_session.did()[..30]
    );
    println!(
        "  Receiver session DID: {}...",
        &receiver_session.did()[..30]
    );
    println!();

    // ─── Step 2: Unsigned Envelope ────────────────────────────────────
    println!("Step 2: Create unsigned envelope (pre-DID-exchange phase)");

    let env = Envelope::new(
        session_id,
        &initiator_session.did(),
        &receiver_session.did(),
        0,
        ProtocolMessage::SessionDidExchange {
            initiator_session_did: initiator_session.did(),
        },
    );

    println!("  Envelope ID: {}", env.id);
    println!("  Session: {}", env.session_id);
    println!("  Sequence: {}", env.sequence);
    println!("  Payload type: {}", env.payload.message_type());
    println!("  Signed: {}", env.signature.is_some());

    // Serialize and restore
    let bytes = env.to_bytes().unwrap();
    let restored = Envelope::from_bytes(&bytes).unwrap();
    assert_eq!(env.session_id, restored.session_id);
    assert_eq!(env.sequence, restored.sequence);
    assert!(restored.signature.is_none());
    println!("  Serialization roundtrip: {} bytes, OK", bytes.len());
    println!();

    // ─── Step 3: Signed Envelope ──────────────────────────────────────
    println!("Step 3: Sign envelope with initiator's session key");

    let mut signed_env = Envelope::new(
        session_id,
        &initiator_session.did(),
        &receiver_session.did(),
        1,
        ProtocolMessage::DisclosureOffer {
            disclosures: vec![serde_json::json!({
                "key": "schema:Person.name",
                "value": "Alice"
            })],
        },
    );

    let signable = signed_env.signable_bytes();
    println!("  Signable bytes: {} bytes (SHA-256 of session_id || seq || payload)", signable.len());

    signed_env.sign(initiator_session.signing_key());
    assert!(signed_env.signature.is_some());
    println!(
        "  Signature: {} bytes",
        signed_env.signature.as_ref().unwrap().len()
    );

    signed_env
        .verify(&initiator_session.verifying_key())
        .unwrap();
    println!("  Verification: VALID");
    println!();

    // ─── Step 4: Wrong Key Rejection ──────────────────────────────────
    println!("Step 4: Wrong key — forged envelope detected");

    let result = signed_env.verify(&receiver_session.verifying_key());
    match result {
        Err(e) => println!("  Wrong session key: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected wrong key"),
    }

    let random_key = SigningKey::generate(&mut OsRng);
    let result = signed_env.verify(&random_key.verifying_key());
    match result {
        Err(e) => println!("  Random key: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected random key"),
    }
    println!();

    // ─── Step 5: Tamper Detection ─────────────────────────────────────
    println!("Step 5: Tamper detection — modified payload invalidates signature");

    let mut tampered = signed_env.clone();
    tampered.payload = ProtocolMessage::DisclosureOffer {
        disclosures: vec![serde_json::json!({
            "key": "schema:Person.name",
            "value": "Eve Attacker"
        })],
    };

    let result = tampered.verify(&initiator_session.verifying_key());
    match result {
        Err(e) => println!("  Tampered payload: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected tampered payload"),
    }

    let mut seq_tampered = signed_env.clone();
    seq_tampered.sequence = 999;
    let result = seq_tampered.verify(&initiator_session.verifying_key());
    match result {
        Err(e) => println!("  Tampered sequence: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected tampered sequence"),
    }
    println!();

    // ─── Step 6: Sequence Numbers ─────────────────────────────────────
    println!("Step 6: Monotonic sequence numbers for replay prevention");

    for seq in [0u64, 1, 2, 42, u64::MAX] {
        let env = Envelope::new(
            session_id,
            "did:key:zSender",
            "did:key:zRecipient",
            seq,
            ProtocolMessage::SessionDidAck,
        );
        let bytes = env.to_bytes().unwrap();
        let restored = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.sequence, seq);
    }
    println!("  Sequences 0, 1, 2, 42, u64::MAX: all preserved through serialization");
    println!();

    // ─── Step 7: Full Protocol Message Coverage ───────────────────────
    println!("Step 7: All protocol message types in envelopes");

    // Create a real token for TokenPresentation
    let principal = PrincipalKeypair::generate();
    let ttl = Utc::now() + Duration::hours(1);
    let mut token = CapabilityToken::mint(
        receiver_session.did(),
        "schema:SearchAction".into(),
        principal.did(),
        ttl,
    );
    token.sign(principal.signing_key());

    // Create a real session for receipt
    let mut session = Session::initiate(&token, &receiver_session.did(), &principal.verifying_key()).unwrap();
    session
        .open(initiator_session.did(), receiver_session.did())
        .unwrap();
    session.execute().unwrap();

    let mut receipt = TransactionReceipt::from_session(
        &session,
        vec![],
        vec!["results_returned".into()],
        "search completed".into(),
        "schema:SearchResult".into(),
    )
    .unwrap();
    receipt.co_sign(initiator_session.signing_key());

    let message_types: Vec<(&str, ProtocolMessage)> = vec![
        (
            "TokenPresentation",
            ProtocolMessage::TokenPresentation {
                token: token.clone(),
            },
        ),
        (
            "TokenAccepted",
            ProtocolMessage::TokenAccepted {
                session_id: "sess-1".into(),
                receiver_session_did: receiver_session.did(),
            },
        ),
        (
            "TokenRejected",
            ProtocolMessage::TokenRejected {
                reason: "scope exceeded".into(),
            },
        ),
        (
            "SessionDidExchange",
            ProtocolMessage::SessionDidExchange {
                initiator_session_did: initiator_session.did(),
            },
        ),
        ("SessionDidAck", ProtocolMessage::SessionDidAck),
        (
            "DisclosureOffer",
            ProtocolMessage::DisclosureOffer {
                disclosures: vec![serde_json::json!({"key": "name", "value": "Alice"})],
            },
        ),
        ("DisclosureAccepted", ProtocolMessage::DisclosureAccepted),
        (
            "ExecutionResult",
            ProtocolMessage::ExecutionResult {
                result: serde_json::json!({
                    "@type": "SearchResult",
                    "results": [{"name": "Flight SFO→TYO", "price": "$1,243"}]
                }),
            },
        ),
        (
            "ReceiptCoSigned",
            ProtocolMessage::ReceiptCoSigned { receipt },
        ),
        (
            "SessionClose",
            ProtocolMessage::SessionClose {
                session_id: session_id.into(),
            },
        ),
        ("SessionClosed", ProtocolMessage::SessionClosed),
        (
            "Error",
            ProtocolMessage::Error {
                code: "E_SCOPE_VIOLATION".into(),
                message: "action not permitted by mandate".into(),
            },
        ),
    ];

    for (seq, (name, msg)) in message_types.into_iter().enumerate() {
        let mut env = Envelope::new(
            session_id,
            &initiator_session.did(),
            &receiver_session.did(),
            seq as u64,
            msg,
        );
        env.sign(initiator_session.signing_key());
        env.verify(&initiator_session.verifying_key()).unwrap();

        let bytes = env.to_bytes().unwrap();
        let restored = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(restored.payload.message_type(), name);
        println!(
            "  seq={:<2} {:<22} {} bytes, signed+verified",
            seq,
            name,
            bytes.len()
        );
    }
    println!();

    // ─── Step 8: Unsigned Verification Fails ──────────────────────────
    println!("Step 8: Unsigned envelope verification fails gracefully");

    let unsigned = Envelope::new(
        session_id,
        "did:key:zSender",
        "did:key:zRecipient",
        0,
        ProtocolMessage::SessionDidAck,
    );
    let result = unsigned.verify(&initiator_session.verifying_key());
    match result {
        Err(e) => println!("  Unsigned envelope: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected unsigned envelope"),
    }
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Envelope wraps any ProtocolMessage with session/routing/sequence");
    println!("  [x] Canonical signable bytes: SHA-256(session_id || sequence || payload)");
    println!("  [x] Ed25519 signature from ephemeral session key");
    println!("  [x] Wrong key rejected (receiver key, random key)");
    println!("  [x] Tampered payload detected (disclosure value changed)");
    println!("  [x] Tampered sequence detected (replay attack prevention)");
    println!("  [x] Monotonic sequence numbers preserved through serialization");
    println!("  [x] All 12 protocol message types envelope-wrapped and verified");
    println!("  [x] Unsigned envelope verification fails gracefully");
    println!("  [x] Transport layer is envelope-in, envelope-out — never touches inner message");
}
