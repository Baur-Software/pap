//! Integration tests for RFC 9458 OHTTP with real HPKE.
//!
//! Tests verify:
//! 1. Key config wire format (RFC 9458 §5)
//! 2. Real HPKE encrypt → decrypt roundtrip (request direction)
//! 3. Real HPKE response roundtrip (response direction, bound to request context)
//! 4. Tamper detection: mutating ciphertext → OhttpDecryptionFailed
//! 5. Passthrough degradation when no recipient public key is configured
//! 6. DID Document PAPObliviousHTTP service → fetch_key_config roundtrip
#![allow(clippy::unwrap_used)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pap_did::DidDocument;
use pap_transport::{
    fetch_key_config, OhttpConfig, OhttpEncryptor, OhttpKeyConfig, OhttpKeyPair,
    OhttpServerDecryptor, TransportError,
};

/// Server keypair generation → wire bytes → from_wire_bytes roundtrip.
///
/// Verifies: `OhttpKeyConfig::to_wire_bytes()` produces exactly 41 bytes in
/// RFC 9458 §5 layout, and `from_wire_bytes` recovers the same key_id and public key.
#[test]
fn ohttp_keypair_and_key_config_roundtrip() {
    let keypair = OhttpKeyPair::generate();
    let pub_key = keypair.public_key_bytes();

    let config = OhttpKeyConfig::new(7, keypair);
    let wire = config.to_wire_bytes();

    // RFC 9458 §5: key_id(1) + kem_id(2) + pub_key(32) + algo_len(2) + kdf(2) + aead(2) = 41
    assert_eq!(wire.len(), 41, "key config must be exactly 41 bytes");
    assert_eq!(wire[0], 7, "key_id must be first byte");

    let (parsed_id, parsed_pub) = OhttpKeyConfig::from_wire_bytes(&wire).unwrap();
    assert_eq!(parsed_id, 7);
    assert_eq!(parsed_pub, pub_key);
}

/// Client `encrypt_request` → server `decrypt_request` with real HPKE.
///
/// Verifies: the encrypted wire bytes differ from plaintext, and the server recovers
/// the original plaintext after HPKE decapsulation + AES-GCM decryption.
#[test]
fn ohttp_hpke_encrypt_decrypt_request() -> Result<(), TransportError> {
    let server_keypair = OhttpKeyPair::generate();
    let pub_key = server_keypair.public_key_bytes();

    let config = OhttpConfig::default()
        .with_recipient_public_key(pub_key.to_vec())
        .with_key_id(1);
    let encryptor = OhttpEncryptor::new(config);
    let server_decryptor = OhttpServerDecryptor::new_with_keypair(server_keypair);

    let plaintext = b"PAP handshake phase 1";
    let (wire, _resp_ctx) = encryptor.encrypt_request(plaintext)?;

    // Wire must be longer: 7 (hdr) + 32 (enc key) + plaintext.len() + 16 (GCM tag)
    assert_eq!(wire.len(), 7 + 32 + plaintext.len() + 16);
    assert_ne!(&wire[39..], plaintext, "ciphertext must differ from plaintext");

    let (decrypted, _) = server_decryptor.decrypt_request(&wire)?;
    assert_eq!(decrypted, plaintext);

    Ok(())
}

/// Server `OhttpResponseEncryptCtx::encrypt_response` → client `OhttpResponseDecryptCtx::decrypt_response`.
///
/// Verifies: response key material is correctly derived from the HPKE context on both sides,
/// producing a symmetric encrypted response that the client can decrypt.
#[test]
fn ohttp_hpke_response_roundtrip() -> Result<(), TransportError> {
    let server_keypair = OhttpKeyPair::generate();
    let pub_key = server_keypair.public_key_bytes();

    let config = OhttpConfig::default()
        .with_recipient_public_key(pub_key.to_vec())
        .with_key_id(1);
    let encryptor = OhttpEncryptor::new(config);
    let server_decryptor = OhttpServerDecryptor::new_with_keypair(server_keypair);

    let req_plaintext = b"query: weather in Berlin";
    let (wire, resp_decrypt_ctx) = encryptor.encrypt_request(req_plaintext)?;
    let (_, resp_encrypt_ctx) = server_decryptor.decrypt_request(&wire)?;

    let resp_plaintext = b"result: 18C, partly cloudy";
    let encrypted_resp = resp_encrypt_ctx.encrypt_response(resp_plaintext)?;

    // Encrypted response must differ from plaintext and include AES-GCM tag overhead
    assert_ne!(encrypted_resp.as_slice(), resp_plaintext);
    assert_eq!(encrypted_resp.len(), resp_plaintext.len() + 16);

    let decrypted_resp = resp_decrypt_ctx.decrypt_response(&encrypted_resp)?;
    assert_eq!(decrypted_resp, resp_plaintext);

    Ok(())
}

/// Tamper detection: mutating the request ciphertext → `OhttpDecryptionFailed`.
///
/// Verifies: AES-GCM authentication tag detects a single-byte corruption in the ciphertext.
#[test]
fn ohttp_tamper_detection_request() -> Result<(), TransportError> {
    let server_keypair = OhttpKeyPair::generate();
    let pub_key = server_keypair.public_key_bytes();

    let config = OhttpConfig::default().with_recipient_public_key(pub_key.to_vec());
    let encryptor = OhttpEncryptor::new(config);
    let server_decryptor = OhttpServerDecryptor::new_with_keypair(server_keypair);

    let (mut wire, _) = encryptor.encrypt_request(b"secret query")?;
    // Flip a byte in the ciphertext region (after the 39-byte header)
    wire[40] ^= 0xff;

    let result = server_decryptor.decrypt_request(&wire);
    assert!(
        matches!(result, Err(TransportError::OhttpDecryptionFailed(_))),
        "tampered request ciphertext must return OhttpDecryptionFailed, got: {:?}",
        result
    );

    Ok(())
}

/// Tamper detection: mutating the response ciphertext → `OhttpDecryptionFailed`.
///
/// Verifies: AES-GCM authentication on the response direction also catches tampering.
#[test]
fn ohttp_tamper_detection_response() -> Result<(), TransportError> {
    let server_keypair = OhttpKeyPair::generate();
    let pub_key = server_keypair.public_key_bytes();

    let config = OhttpConfig::default().with_recipient_public_key(pub_key.to_vec());
    let encryptor = OhttpEncryptor::new(config);
    let server_decryptor = OhttpServerDecryptor::new_with_keypair(server_keypair);

    let (wire, resp_decrypt_ctx) = encryptor.encrypt_request(b"hello")?;
    let (_, resp_encrypt_ctx) = server_decryptor.decrypt_request(&wire)?;

    let mut encrypted_resp = resp_encrypt_ctx.encrypt_response(b"world")?;
    // Flip the last byte (part of the GCM tag)
    let last = encrypted_resp.len() - 1;
    encrypted_resp[last] ^= 0x01;

    let result = resp_decrypt_ctx.decrypt_response(&encrypted_resp);
    assert!(
        matches!(result, Err(TransportError::OhttpDecryptionFailed(_))),
        "tampered response ciphertext must return OhttpDecryptionFailed, got: {:?}",
        result
    );

    Ok(())
}

/// `OhttpConfig::default()` (no recipient public key) → passthrough: no encryption.
///
/// Verifies: when `recipient_public_key` is None, wire bytes equal the plaintext and
/// the server (in passthrough mode) returns the same bytes unchanged.
#[test]
fn ohttp_passthrough_no_recipient_key() -> Result<(), TransportError> {
    let config = OhttpConfig::default(); // no recipient_public_key
    let encryptor = OhttpEncryptor::new(config.clone());
    let server_decryptor = OhttpServerDecryptor::new(config); // passthrough mode

    let plaintext = b"direct connection, no OHTTP wrapping";
    let (wire, resp_ctx) = encryptor.encrypt_request(plaintext)?;

    // Passthrough: wire bytes equal plaintext (no OHTTP header)
    assert_eq!(&wire, plaintext, "passthrough must return plaintext unchanged");

    let (decrypted, enc_ctx) = server_decryptor.decrypt_request(&wire)?;
    assert_eq!(decrypted, plaintext);

    // Response passthrough: also identity
    let resp = enc_ctx.encrypt_response(b"response")?;
    assert_eq!(&resp, b"response");

    let decrypted_resp = resp_ctx.decrypt_response(&resp)?;
    assert_eq!(&decrypted_resp, b"response");

    Ok(())
}

/// DID Document `PAPObliviousHTTP` service → `fetch_key_config` → correct public key.
///
/// Verifies: `fetch_key_config` locates the service entry, base64url-decodes
/// `ohthpKeyConfig`, parses the wire bytes, and returns an `OhttpConfig` whose
/// `recipient_public_key` matches the original keypair's public key.
#[test]
fn ohttp_key_config_from_did_document() -> Result<(), TransportError> {
    let keypair = OhttpKeyPair::generate();
    let pub_key = keypair.public_key_bytes();
    let key_config = OhttpKeyConfig::new(3, keypair);
    let wire_bytes = key_config.to_wire_bytes();
    let wire_b64 = URL_SAFE_NO_PAD.encode(&wire_bytes);

    // Build a minimal DID Document with a PAPObliviousHTTP service entry
    let doc_json = format!(
        r#"{{
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:key:ztest",
            "verificationMethod": [{{
                "id": "did:key:ztest#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:key:ztest",
                "publicKeyMultibase": "z1234"
            }}],
            "authentication": ["did:key:ztest#key-1"],
            "service": [{{
                "id": "did:key:ztest#pap-ohttp",
                "type": "PAPObliviousHTTP",
                "serviceEndpoint": "https://node.example/pap/ohttp",
                "ohthpKeyConfig": "{wire_b64}"
            }}]
        }}"#
    );

    let did_doc: DidDocument = serde_json::from_str(&doc_json).expect("valid DID Document JSON");
    let config = fetch_key_config(&did_doc)?;

    assert_eq!(
        config.key_id, 3,
        "key_id must match the value from key config wire bytes"
    );
    assert_eq!(
        config.recipient_public_key.as_deref(),
        Some(pub_key.as_slice()),
        "recipient_public_key must match the original keypair's public key"
    );

    Ok(())
}

/// OHTTP config relay resolution still works after the new fields are added.
#[test]
fn ohttp_config_relay_resolution() {
    let config = OhttpConfig::default().with_relay(Some("http://relay.example.com".into()));
    assert_eq!(
        config.resolve_relay(),
        Some("http://relay.example.com".into())
    );

    let config = OhttpConfig::default().with_relay(None);
    if std::env::var("PAP_OHTTP_RELAY_URL").is_err() {
        assert_eq!(config.resolve_relay(), None);
    }
}
