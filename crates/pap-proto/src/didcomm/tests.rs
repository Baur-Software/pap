use base64::Engine;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use crate::didcomm::types::{DIDCommPlaintext, DIDCommSigned, JwsSignature};
use crate::didcomm::{DIDCommToPap, PapToDIDComm};
use crate::envelope::Envelope;
use crate::message::ProtocolMessage;

fn make_envelope(payload: ProtocolMessage) -> Envelope {
    Envelope::new(
        "session-abc",
        "did:key:zSender",
        "did:key:zRecipient",
        1,
        payload,
    )
}

fn make_signed_envelope() -> (Envelope, SigningKey) {
    let key = SigningKey::generate(&mut OsRng);
    let mut env = make_envelope(ProtocolMessage::DisclosureAccepted);
    env.sign(&key);
    (env, key)
}

// ── Plaintext round-trip ─────────────────────────────────────────

#[test]
fn plaintext_roundtrip_session_did_ack() {
    let env = make_envelope(ProtocolMessage::SessionDidAck);
    let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();

    assert_eq!(plaintext.typ, "application/didcomm-plain+json");
    assert!(plaintext.type_uri.ends_with("/session-did-ack"));
    assert_eq!(plaintext.from.as_deref(), Some("did:key:zSender"));
    assert_eq!(plaintext.to, vec!["did:key:zRecipient"]);

    let restored = DIDCommToPap::from_plaintext(&plaintext).unwrap();
    assert_eq!(restored.session_id, env.session_id);
    assert_eq!(restored.sender, env.sender);
    assert_eq!(restored.recipient, env.recipient);
    assert_eq!(restored.sequence, env.sequence);
    assert_eq!(restored.payload.message_type(), env.payload.message_type());
}

#[test]
fn plaintext_roundtrip_execution_result() {
    let env = make_envelope(ProtocolMessage::ExecutionResult {
        result: serde_json::json!({"@type": "Flight", "status": "confirmed", "price": 450}),
    });
    let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();
    assert!(plaintext.type_uri.ends_with("/execution-result"));

    let restored = DIDCommToPap::from_plaintext(&plaintext).unwrap();
    assert_eq!(restored.payload.message_type(), "ExecutionResult");
}

#[test]
fn plaintext_roundtrip_preserves_pap_signature() {
    let (env, key) = make_signed_envelope();
    assert!(env.signature.is_some());

    let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();
    let restored = DIDCommToPap::from_plaintext(&plaintext).unwrap();

    // PAP-level signature is preserved through the DIDComm layer
    assert!(restored.signature.is_some());
    let vk = key.verifying_key();
    restored.verify(&vk).unwrap();
}

#[test]
fn plaintext_roundtrip_all_message_types() {
    let messages = vec![
        ProtocolMessage::TokenPresentation {
            token: dummy_token(),
        },
        ProtocolMessage::TokenAccepted {
            session_id: "s1".into(),
            receiver_session_did: "did:key:zR".into(),
        },
        ProtocolMessage::TokenRejected {
            reason: "expired".into(),
        },
        ProtocolMessage::SessionDidExchange {
            initiator_session_did: "did:key:zI".into(),
        },
        ProtocolMessage::SessionDidAck,
        ProtocolMessage::DisclosureOffer {
            disclosures: vec![serde_json::json!({"key": "name"})],
        },
        ProtocolMessage::DisclosureAccepted,
        ProtocolMessage::ExecutionResult {
            result: serde_json::json!({}),
        },
        ProtocolMessage::SessionClose {
            session_id: "s1".into(),
        },
        ProtocolMessage::SessionClosed,
        ProtocolMessage::Error {
            code: "E001".into(),
            message: "test error".into(),
        },
    ];

    for msg in messages {
        let expected_type = msg.message_type();
        let env = make_envelope(msg);
        let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();
        let restored = DIDCommToPap::from_plaintext(&plaintext).unwrap();
        assert_eq!(
            restored.payload.message_type(),
            expected_type,
            "round-trip failed for {expected_type}"
        );
    }
}

// ── JWS signed message ──────────────────────────────────────────

#[test]
fn jws_sign_verify_roundtrip() {
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    let env = make_envelope(ProtocolMessage::DisclosureAccepted);

    let signed = PapToDIDComm::to_signed(&env, &key).unwrap();
    assert!(!signed.payload.is_empty());
    assert_eq!(signed.signatures.len(), 1);

    let restored = DIDCommToPap::from_signed(&signed, &vk).unwrap();
    assert_eq!(restored.session_id, env.session_id);
    assert_eq!(restored.payload.message_type(), "DisclosureAccepted");
}

#[test]
fn jws_wrong_key_fails_verification() {
    let key = SigningKey::generate(&mut OsRng);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionClosed);

    let signed = PapToDIDComm::to_signed(&env, &key).unwrap();
    let result = DIDCommToPap::from_signed(&signed, &wrong_key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn jws_tampered_payload_fails() {
    let key = SigningKey::generate(&mut OsRng);
    let vk = key.verifying_key();
    let env = make_envelope(ProtocolMessage::ExecutionResult {
        result: serde_json::json!({"price": 100}),
    });

    let mut signed = PapToDIDComm::to_signed(&env, &key).unwrap();

    // Tamper with the payload
    let env2 = make_envelope(ProtocolMessage::ExecutionResult {
        result: serde_json::json!({"price": 999}),
    });
    let tampered_plaintext = PapToDIDComm::to_plaintext(&env2).unwrap();
    let tampered_json = serde_json::to_string(&tampered_plaintext).unwrap();
    signed.payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tampered_json.as_bytes());

    let result = DIDCommToPap::from_signed(&signed, &vk);
    assert!(result.is_err());
}

#[test]
fn jws_preserves_pap_envelope_signature() {
    let (env, pap_key) = make_signed_envelope();
    let didcomm_key = SigningKey::generate(&mut OsRng);

    // Sign with a different DIDComm-level key
    let signed = PapToDIDComm::to_signed(&env, &didcomm_key).unwrap();
    let restored = DIDCommToPap::from_signed(&signed, &didcomm_key.verifying_key()).unwrap();

    // PAP-level signature still verifies with the original key
    restored.verify(&pap_key.verifying_key()).unwrap();
}

#[test]
fn jws_empty_signatures_fails() {
    let signed = DIDCommSigned {
        payload: String::new(),
        signatures: vec![],
    };
    let key = SigningKey::generate(&mut OsRng);
    let result = DIDCommToPap::from_signed(&signed, &key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn jws_serialization_roundtrip() {
    let key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionDidAck);

    let signed = PapToDIDComm::to_signed(&env, &key).unwrap();
    let json = serde_json::to_string(&signed).unwrap();
    let deserialized: DIDCommSigned = serde_json::from_str(&json).unwrap();

    // Verify the deserialized signed message
    let restored = DIDCommToPap::from_signed(&deserialized, &key.verifying_key()).unwrap();
    assert_eq!(restored.session_id, env.session_id);
}

// ── JWE encrypted message ───────────────────────────────────────

#[test]
fn jwe_encrypt_decrypt_roundtrip() {
    let recipient_key = SigningKey::generate(&mut OsRng);
    let recipient_vk = recipient_key.verifying_key();
    let env = make_envelope(ProtocolMessage::DisclosureOffer {
        disclosures: vec![serde_json::json!({"schema:name": "Alice"})],
    });

    let encrypted = PapToDIDComm::to_encrypted(&env, &recipient_vk).unwrap();
    assert!(!encrypted.ciphertext.is_empty());
    assert!(!encrypted.iv.is_empty());
    assert!(!encrypted.tag.is_empty());
    assert_eq!(encrypted.recipients.len(), 1);

    let restored = DIDCommToPap::from_encrypted(&encrypted, &recipient_key).unwrap();
    assert_eq!(restored.session_id, env.session_id);
    assert_eq!(restored.sender, env.sender);
    assert_eq!(restored.recipient, env.recipient);
    assert_eq!(restored.payload.message_type(), "DisclosureOffer");
}

#[test]
fn jwe_wrong_key_fails_decryption() {
    let recipient_key = SigningKey::generate(&mut OsRng);
    let wrong_key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionClosed);

    let encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();
    let result = DIDCommToPap::from_encrypted(&encrypted, &wrong_key);
    assert!(result.is_err());
}

#[test]
fn jwe_tampered_ciphertext_fails() {
    let recipient_key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionDidAck);

    let mut encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();

    // Tamper with the ciphertext
    let mut ct_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .unwrap();
    if let Some(b) = ct_bytes.first_mut() {
        *b ^= 0xff;
    }
    encrypted.ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&ct_bytes);

    let result = DIDCommToPap::from_encrypted(&encrypted, &recipient_key);
    assert!(result.is_err());
}

#[test]
fn jwe_tampered_header_fails() {
    let recipient_key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionDidAck);

    let mut encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();

    // Tamper with the protected header (AAD)
    let mut header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encrypted.protected_header)
        .unwrap();
    // Change a byte in the header
    if let Some(b) = header_bytes.last_mut() {
        *b ^= 0x01;
    }
    encrypted.protected_header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&header_bytes);

    let result = DIDCommToPap::from_encrypted(&encrypted, &recipient_key);
    assert!(result.is_err());
}

#[test]
fn jwe_preserves_pap_signature() {
    let (env, pap_key) = make_signed_envelope();
    let recipient_key = SigningKey::generate(&mut OsRng);

    let encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();
    let restored = DIDCommToPap::from_encrypted(&encrypted, &recipient_key).unwrap();

    // PAP-level signature survives encryption round-trip
    restored.verify(&pap_key.verifying_key()).unwrap();
}

#[test]
fn jwe_serialization_roundtrip() {
    let recipient_key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionDidAck);

    let encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();
    let json = serde_json::to_string(&encrypted).unwrap();
    let deserialized: crate::didcomm::types::DIDCommEncrypted =
        serde_json::from_str(&json).unwrap();

    let restored = DIDCommToPap::from_encrypted(&deserialized, &recipient_key).unwrap();
    assert_eq!(restored.session_id, env.session_id);
}

#[test]
fn jwe_protected_header_contains_expected_fields() {
    let recipient_key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionDidAck);

    let encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encrypted.protected_header)
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

    assert_eq!(header["typ"], "application/didcomm-encrypted+json");
    assert_eq!(header["alg"], "ECDH-ES");
    assert_eq!(header["enc"], "A256GCM");
    assert_eq!(header["epk"]["kty"], "OKP");
    assert_eq!(header["epk"]["crv"], "X25519");
    assert!(header["epk"]["x"].is_string());
    assert!(header["apv"].is_string());
}

// ── Full round-trip: PAP → DIDComm → wire → DIDComm → PAP ─────

#[test]
fn full_roundtrip_signed_with_wire_serialization() {
    let session_key = SigningKey::generate(&mut OsRng);
    let didcomm_key = SigningKey::generate(&mut OsRng);

    // Build a PAP envelope with signature
    let mut env = Envelope::new(
        "session-roundtrip",
        "did:key:zInitiator",
        "did:key:zReceiver",
        5,
        ProtocolMessage::ExecutionResult {
            result: serde_json::json!({
                "@type": "SearchAction",
                "result": {"@type": "Flight", "price": 350}
            }),
        },
    );
    env.sign(&session_key);

    // PAP → DIDComm signed
    let signed = PapToDIDComm::to_signed(&env, &didcomm_key).unwrap();

    // Serialize to wire format (JSON)
    let wire_bytes = serde_json::to_vec(&signed).unwrap();

    // Deserialize from wire
    let received: DIDCommSigned = serde_json::from_slice(&wire_bytes).unwrap();

    // DIDComm → PAP
    let restored = DIDCommToPap::from_signed(&received, &didcomm_key.verifying_key()).unwrap();

    // Verify all PAP semantics preserved
    assert_eq!(restored.session_id, "session-roundtrip");
    assert_eq!(restored.sender, "did:key:zInitiator");
    assert_eq!(restored.recipient, "did:key:zReceiver");
    assert_eq!(restored.sequence, 5);
    assert_eq!(restored.payload.message_type(), "ExecutionResult");

    // PAP signature still valid
    restored.verify(&session_key.verifying_key()).unwrap();
}

#[test]
fn full_roundtrip_encrypted_with_wire_serialization() {
    let session_key = SigningKey::generate(&mut OsRng);
    let recipient_key = SigningKey::generate(&mut OsRng);

    let mut env = Envelope::new(
        "session-encrypted",
        "did:key:zInitiator",
        "did:key:zReceiver",
        3,
        ProtocolMessage::DisclosureOffer {
            disclosures: vec![serde_json::json!({
                "schema:Person": {"schema:name": "Alice"}
            })],
        },
    );
    env.sign(&session_key);

    // PAP → DIDComm encrypted
    let encrypted = PapToDIDComm::to_encrypted(&env, &recipient_key.verifying_key()).unwrap();

    // Wire serialization
    let wire = serde_json::to_vec(&encrypted).unwrap();
    let received: crate::didcomm::types::DIDCommEncrypted = serde_json::from_slice(&wire).unwrap();

    // DIDComm → PAP
    let restored = DIDCommToPap::from_encrypted(&received, &recipient_key).unwrap();

    assert_eq!(restored.session_id, "session-encrypted");
    assert_eq!(restored.sequence, 3);
    assert_eq!(restored.payload.message_type(), "DisclosureOffer");
    restored.verify(&session_key.verifying_key()).unwrap();
}

// ── DIDComm type URI mapping ────────────────────────────────────

#[test]
fn type_uri_maps_all_pap_message_types() {
    let cases = vec![
        (
            ProtocolMessage::TokenPresentation {
                token: dummy_token(),
            },
            "token-presentation",
        ),
        (
            ProtocolMessage::TokenAccepted {
                session_id: "s".into(),
                receiver_session_did: "d".into(),
            },
            "token-accepted",
        ),
        (
            ProtocolMessage::TokenRejected { reason: "r".into() },
            "token-rejected",
        ),
        (
            ProtocolMessage::SessionDidExchange {
                initiator_session_did: "d".into(),
            },
            "session-did-exchange",
        ),
        (ProtocolMessage::SessionDidAck, "session-did-ack"),
        (
            ProtocolMessage::DisclosureOffer {
                disclosures: vec![],
            },
            "disclosure-offer",
        ),
        (ProtocolMessage::DisclosureAccepted, "disclosure-accepted"),
        (
            ProtocolMessage::ExecutionResult {
                result: serde_json::json!({}),
            },
            "execution-result",
        ),
        (
            ProtocolMessage::SessionClose {
                session_id: "s".into(),
            },
            "session-close",
        ),
        (ProtocolMessage::SessionClosed, "session-closed"),
        (
            ProtocolMessage::Error {
                code: "E".into(),
                message: "m".into(),
            },
            "error",
        ),
    ];

    for (msg, expected_slug) in cases {
        let env = make_envelope(msg);
        let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();
        let expected_uri = format!("https://pap.baur.dev/proto/1.0/{expected_slug}");
        assert_eq!(
            plaintext.type_uri, expected_uri,
            "wrong type URI for {expected_slug}"
        );
    }
}

// ── Edge cases ──────────────────────────────────────────────────

#[test]
fn plaintext_invalid_body_fails_restoration() {
    let plaintext = DIDCommPlaintext {
        id: "test".into(),
        typ: "application/didcomm-plain+json".into(),
        type_uri: "https://pap.baur.dev/proto/1.0/session-did-ack".into(),
        from: None,
        to: vec![],
        created_time: None,
        body: serde_json::json!({"not": "an envelope"}),
    };
    let result = DIDCommToPap::from_plaintext(&plaintext);
    assert!(result.is_err());
}

#[test]
fn jws_bad_algorithm_rejected() {
    let key = SigningKey::generate(&mut OsRng);
    let env = make_envelope(ProtocolMessage::SessionDidAck);
    let mut signed = PapToDIDComm::to_signed(&env, &key).unwrap();

    // Replace protected header with non-EdDSA algorithm
    let bad_header = serde_json::json!({"typ": "application/didcomm-signed+json", "alg": "RS256"});
    signed.signatures[0].protected_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_string(&bad_header).unwrap().as_bytes());

    let result = DIDCommToPap::from_signed(&signed, &key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn jws_invalid_signature_encoding_fails() {
    let signed = DIDCommSigned {
        payload: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"{}"),
        signatures: vec![JwsSignature {
            protected_header: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::json!({"typ": "application/didcomm-signed+json", "alg": "EdDSA"})
                    .to_string()
                    .as_bytes(),
            ),
            signature: "not-valid-base64!!!".into(),
        }],
    };
    let key = SigningKey::generate(&mut OsRng);
    let result = DIDCommToPap::from_signed(&signed, &key.verifying_key());
    assert!(result.is_err());
}

#[test]
fn unsigned_envelope_survives_plaintext_roundtrip() {
    // Envelope without PAP-level signature (Phase 1)
    let env = make_envelope(ProtocolMessage::TokenPresentation {
        token: dummy_token(),
    });
    assert!(env.signature.is_none());

    let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();
    let restored = DIDCommToPap::from_plaintext(&plaintext).unwrap();
    assert!(restored.signature.is_none());
    assert_eq!(restored.payload.message_type(), "TokenPresentation");
}

#[test]
fn sequence_zero_and_max_preserved() {
    for seq in [0, 1, u64::MAX] {
        let env = Envelope::new(
            "s",
            "did:key:zA",
            "did:key:zB",
            seq,
            ProtocolMessage::SessionClosed,
        );
        let plaintext = PapToDIDComm::to_plaintext(&env).unwrap();
        let restored = DIDCommToPap::from_plaintext(&plaintext).unwrap();
        assert_eq!(restored.sequence, seq);
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn dummy_token() -> pap_core::session::CapabilityToken {
    use chrono::{Duration, Utc};
    pap_core::session::CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:SearchAction".into(),
        "did:key:zIssuer".into(),
        Utc::now() + Duration::hours(1),
    )
}
