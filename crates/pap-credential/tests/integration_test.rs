//! Integration tests for credential layer covering edge cases and full flows

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use pap_credential::{Disclosure, SelectiveDisclosureJwt, VerifiableCredential};
use rand::rngs::OsRng;
use std::collections::HashMap;

fn make_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn did_from_key(key: &SigningKey) -> String {
    pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
        .unwrap()
        .did()
}

#[test]
fn vc_expired_credential_check() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut vc = VerifiableCredential::from_mandate(
        &did,
        serde_json::json!({"id": "did:key:zagent"}),
        Some(Utc::now() - Duration::hours(1)), // already expired
    );
    vc.sign(&key, &format!("{did}#key-1"));

    assert!(vc.is_expired());
    assert!(vc.verify(&key.verifying_key()).is_ok()); // signature still valid
}

#[test]
fn vc_without_expiration() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let vc = VerifiableCredential::from_mandate(
        &did,
        serde_json::json!({"id": "did:key:zagent"}),
        None, // no expiration
    );

    assert!(!vc.is_expired());
}

#[test]
fn vc_unsigned_verification_fails() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let vc =
        VerifiableCredential::from_mandate(&did, serde_json::json!({"id": "did:key:zagent"}), None);

    // No signature, should fail
    assert!(vc.verify(&key.verifying_key()).is_err());
}

#[test]
fn vc_hash_stability() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let vc = VerifiableCredential::from_mandate(
        &did,
        serde_json::json!({"id": "did:key:zagent", "scope": ["schema:SearchAction"]}),
        None,
    );

    let hash1 = vc.hash();
    let hash2 = vc.hash();

    assert_eq!(hash1, hash2, "Hash should be deterministic");
    assert!(!hash1.is_empty());
}

#[test]
fn vc_complex_mandate_payload() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let complex_payload = serde_json::json!({
        "id": "did:key:zagent",
        "scope": ["schema:SearchAction", "schema:PayAction"],
        "disclosure": ["schema:name", "schema:email"],
        "ttl": "2026-12-31T23:59:59Z",
        "payment_proof": "ecash:blind:v1:token=abc123"
    });

    let mut vc = VerifiableCredential::from_mandate(
        &did,
        complex_payload,
        Some(Utc::now() + Duration::days(365)),
    );
    vc.sign(&key, &format!("{did}#key-1"));

    assert!(vc.verify(&key.verifying_key()).is_ok());

    // Roundtrip
    let json = vc.to_json();
    let vc2: VerifiableCredential = serde_json::from_str(&json).unwrap();
    assert_eq!(vc.id, vc2.id);
    assert_eq!(vc.credential_subject, vc2.credential_subject);
}

#[test]
fn sd_jwt_full_disclosure_flow() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut claims = HashMap::new();
    claims.insert("schema:name".into(), serde_json::json!("Alice"));
    claims.insert(
        "schema:email".into(),
        serde_json::json!("alice@example.com"),
    );
    claims.insert("schema:address".into(), serde_json::json!("123 Main St"));

    let mut sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    sd_jwt.sign(&key).unwrap();

    // Disclose all claims
    let disclosures = sd_jwt
        .disclose(&["schema:name", "schema:email", "schema:address"])
        .unwrap();
    assert_eq!(disclosures.len(), 3);

    // Verify all
    assert!(sd_jwt
        .verify_disclosures(&disclosures, &key.verifying_key())
        .is_ok());
}

#[test]
fn sd_jwt_partial_disclosure_subset() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut claims = HashMap::new();
    claims.insert("schema:name".into(), serde_json::json!("Bob"));
    claims.insert("schema:email".into(), serde_json::json!("bob@example.com"));
    claims.insert("schema:ssn".into(), serde_json::json!("123-45-6789"));

    let mut sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    sd_jwt.sign(&key).unwrap();

    // Disclose only name, keep email and SSN private
    let disclosures = sd_jwt.disclose(&["schema:name"]).unwrap();
    assert_eq!(disclosures.len(), 1);
    assert_eq!(disclosures[0].key, "schema:name");

    assert!(sd_jwt
        .verify_disclosures(&disclosures, &key.verifying_key())
        .is_ok());
}

#[test]
fn sd_jwt_unsigned_fails() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut claims = HashMap::new();
    claims.insert("schema:name".into(), serde_json::json!("Alice"));

    let sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    // Not signed

    let disclosures = sd_jwt.disclose(&["schema:name"]).unwrap();
    assert!(sd_jwt
        .verify_disclosures(&disclosures, &key.verifying_key())
        .is_err());
}

#[test]
fn sd_jwt_disclosure_hash_uniqueness() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut claims = HashMap::new();
    claims.insert("claim1".into(), serde_json::json!("value1"));
    claims.insert("claim2".into(), serde_json::json!("value2"));

    let mut sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    sd_jwt.sign(&key).unwrap();

    let d1 = sd_jwt.disclose(&["claim1"]).unwrap();
    let d2 = sd_jwt.disclose(&["claim2"]).unwrap();

    // Different claims should have different hashes
    assert_ne!(d1[0].hash(), d2[0].hash());
}

#[test]
fn sd_jwt_claim_keys_list() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let mut claims = HashMap::new();
    claims.insert("a".into(), serde_json::json!(1));
    claims.insert("b".into(), serde_json::json!(2));
    claims.insert("c".into(), serde_json::json!(3));

    let sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    let keys = sd_jwt.claim_keys();

    assert_eq!(keys.len(), 3);
    assert!(keys.contains(&"a"));
    assert!(keys.contains(&"b"));
    assert!(keys.contains(&"c"));
}

#[test]
fn sd_jwt_empty_claims() {
    let key = make_keypair();
    let did = did_from_key(&key);

    let claims = HashMap::new();
    let mut sd_jwt = SelectiveDisclosureJwt::new(did, claims);
    sd_jwt.sign(&key).unwrap();

    let disclosures = sd_jwt.disclose(&[]).unwrap();
    assert!(disclosures.is_empty());
    assert!(sd_jwt
        .verify_disclosures(&disclosures, &key.verifying_key())
        .is_ok());
}

#[test]
fn disclosure_serialization_roundtrip() {
    let d = Disclosure {
        salt: "random-salt".into(),
        key: "schema:name".into(),
        value: serde_json::json!("Alice"),
    };

    let json = serde_json::to_string(&d).unwrap();
    let d2: Disclosure = serde_json::from_str(&json).unwrap();

    assert_eq!(d.salt, d2.salt);
    assert_eq!(d.key, d2.key);
    assert_eq!(d.value, d2.value);
}
