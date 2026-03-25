//! Credential Lifecycle PoC demonstrating:
//!
//! - W3C Verifiable Credential (VC Data Model 2.0) issuance and verification
//! - SD-JWT (Selective Disclosure JWT) creation and selective claim reveal
//! - Zero-disclosure: signed SD-JWT verified without revealing any claims
//! - Partial disclosure: reveal only mandate-permitted properties
//! - Tamper detection: modified claims rejected by hash commitment
//! - Wrong-key rejection: forged credentials detected
//! - VC wrapping a mandate as credentialSubject (interop with VC ecosystems)
//! - Full credential lifecycle: issue → sign → verify → disclose → verify
//!
//! This example focuses on the credential layer in isolation, showing how
//! PAP's privacy guarantees are implemented at the cryptographic level.

use std::collections::HashMap;

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use pap_credential::{SelectiveDisclosureJwt, VerifiableCredential};
use pap_did::PrincipalKeypair;
use rand::rngs::OsRng;

fn main() {
    println!("=== PAP Credential Lifecycle Example ===");
    println!("Principal Agent Protocol v0.4.2 — Credentials Deep Dive\n");

    // ─── Step 1: W3C Verifiable Credential ────────────────────────────
    println!("Step 1: Issue and sign a W3C Verifiable Credential");

    let issuer_key = SigningKey::generate(&mut OsRng);
    let issuer_kp = PrincipalKeypair::from_bytes(&issuer_key.to_bytes()).unwrap();
    let issuer_did = issuer_kp.did();
    let key_id = format!("{issuer_did}#key-1");

    let agent_kp = PrincipalKeypair::generate();
    let agent_did = agent_kp.did();

    let subject = serde_json::json!({
        "id": agent_did,
        "scope": ["schema:SearchAction", "schema:ReserveAction"],
        "maxDelegationDepth": 2,
        "disclosure": {
            "permitted": ["schema:Person.name"],
            "prohibited": ["schema:Person.ssn"]
        }
    });

    let expiration = Utc::now() + Duration::hours(24);
    let mut vc = VerifiableCredential::from_mandate(&issuer_did, subject, Some(expiration));

    println!("  VC ID: {}", vc.id);
    println!("  Issuer: {}...", &issuer_did[..30]);
    println!("  Subject: {}...", &agent_did[..30]);
    println!("  Type: {:?}", vc.credential_type);
    println!(
        "  Context: W3C Credentials v2 ({})",
        vc.context.first().unwrap()
    );
    println!("  Expired: {}", vc.is_expired());

    vc.sign(&issuer_key, &key_id);
    let proof = vc.proof.as_ref().unwrap();
    println!("  Proof type: {}", proof.proof_type);
    println!("  Proof purpose: {}", proof.proof_purpose);
    println!(
        "  Verification method: {}...",
        &proof.verification_method[..30]
    );
    println!();

    // ─── Step 2: VC Verification ──────────────────────────────────────
    println!("Step 2: Verify the credential");

    vc.verify(&issuer_key.verifying_key()).unwrap();
    println!("  Signature: VALID");

    let wrong_key = SigningKey::generate(&mut OsRng);
    let result = vc.verify(&wrong_key.verifying_key());
    match result {
        Err(e) => println!("  Wrong key: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected wrong key"),
    }

    // JSON roundtrip
    let json = vc.to_json();
    let vc_restored: VerifiableCredential = serde_json::from_str(&json).unwrap();
    assert_eq!(vc.id, vc_restored.id);
    vc_restored.verify(&issuer_key.verifying_key()).unwrap();
    println!("  JSON roundtrip: VALID (serialized {} bytes)", json.len());

    // Content hash
    let hash = vc.hash();
    println!("  Content hash: {}...", &hash[..24]);
    println!();

    // ─── Step 3: SD-JWT Creation ──────────────────────────────────────
    println!("Step 3: Create an SD-JWT with personal claims");

    let holder_key = SigningKey::generate(&mut OsRng);
    let holder_kp = PrincipalKeypair::from_bytes(&holder_key.to_bytes()).unwrap();
    let holder_did = holder_kp.did();

    let mut claims = HashMap::new();
    claims.insert("schema:name".into(), serde_json::json!("Alice Nakamoto"));
    claims.insert(
        "schema:email".into(),
        serde_json::json!("alice@example.com"),
    );
    claims.insert("schema:nationality".into(), serde_json::json!("Wonderland"));
    claims.insert("schema:birthDate".into(), serde_json::json!("1990-01-15"));
    claims.insert("schema:telephone".into(), serde_json::json!("+1-555-0199"));

    let mut sd_jwt = SelectiveDisclosureJwt::new(holder_did.clone(), claims);
    sd_jwt.sign(&holder_key);

    let mut claim_keys = sd_jwt.claim_keys();
    claim_keys.sort();
    println!("  Issuer: {}...", &holder_did[..30]);
    println!("  Claims: {}", claim_keys.len());
    for key in &claim_keys {
        println!("    - {key}");
    }
    println!("  Signed: {}", sd_jwt.signature.is_some());
    println!();

    // ─── Step 4: Zero Disclosure ──────────────────────────────────────
    println!("Step 4: Zero-disclosure verification (no claims revealed)");

    let zero_disclosures = sd_jwt.disclose(&[]).unwrap();
    assert!(zero_disclosures.is_empty());
    sd_jwt
        .verify_disclosures(&zero_disclosures, &holder_key.verifying_key())
        .unwrap();
    println!("  Disclosed: 0 claims");
    println!("  Signature verified: YES (proves holder identity without revealing data)");
    println!();

    // ─── Step 5: Partial Disclosure ───────────────────────────────────
    println!("Step 5: Selective disclosure — reveal only name and email");

    let partial = sd_jwt.disclose(&["schema:name", "schema:email"]).unwrap();
    assert_eq!(partial.len(), 2);
    println!(
        "  Disclosed {} of {} claims:",
        partial.len(),
        claim_keys.len()
    );
    for d in &partial {
        println!("    {} = {} (salt: {}...)", d.key, d.value, &d.salt[..8]);
    }

    sd_jwt
        .verify_disclosures(&partial, &holder_key.verifying_key())
        .unwrap();
    println!("  Disclosure verification: VALID");
    println!("  Hidden claims: nationality, birthDate, telephone (never sent)");
    println!();

    // ─── Step 6: Full Disclosure ──────────────────────────────────────
    println!("Step 6: Full disclosure — all claims revealed");

    let key_refs: Vec<&str> = claim_keys.to_vec();
    let full = sd_jwt.disclose(&key_refs).unwrap();
    assert_eq!(full.len(), 5);
    sd_jwt
        .verify_disclosures(&full, &holder_key.verifying_key())
        .unwrap();
    println!("  Disclosed: all {} claims", full.len());
    println!("  Verification: VALID");
    println!();

    // ─── Step 7: Tamper Detection ─────────────────────────────────────
    println!("Step 7: Tamper detection — modified claim rejected");

    let mut tampered = sd_jwt.disclose(&["schema:name"]).unwrap();
    tampered[0].value = serde_json::json!("Bob Forgery");
    let result = sd_jwt.verify_disclosures(&tampered, &holder_key.verifying_key());
    match result {
        Err(e) => println!("  Tampered name: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected tampered disclosure"),
    }

    let mut tampered_salt = sd_jwt.disclose(&["schema:email"]).unwrap();
    tampered_salt[0].salt = "forged-salt-value".into();
    let result = sd_jwt.verify_disclosures(&tampered_salt, &holder_key.verifying_key());
    match result {
        Err(e) => println!("  Tampered salt: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected tampered salt"),
    }
    println!();

    // ─── Step 8: Wrong Key Rejection ──────────────────────────────────
    println!("Step 8: Wrong key — forged SD-JWT detected");

    let forger_key = SigningKey::generate(&mut OsRng);
    let result = sd_jwt.verify_signature(&forger_key.verifying_key());
    match result {
        Err(e) => println!("  Wrong issuer key: REJECTED ({e})"),
        Ok(()) => panic!("should have rejected wrong key"),
    }
    println!();

    // ─── Step 9: Nonexistent Claim ────────────────────────────────────
    println!("Step 9: Nonexistent claim request rejected");

    let result = sd_jwt.disclose(&["schema:ssn"]);
    match result {
        Err(e) => println!("  schema:ssn: REJECTED ({e})"),
        Ok(_) => panic!("should have rejected nonexistent claim"),
    }
    println!();

    // ─── Step 10: Credential-to-SD-JWT Pipeline ──────────────────────
    println!("Step 10: VC → SD-JWT pipeline (issue credential, then selectively disclose)");

    // Issue a VC containing mandate claims
    let mandate_subject = serde_json::json!({
        "id": agent_did,
        "scope": "schema:SearchAction",
        "maxBudget": 500
    });
    let mut mandate_vc = VerifiableCredential::from_mandate(
        &issuer_did,
        mandate_subject,
        Some(Utc::now() + Duration::hours(1)),
    );
    mandate_vc.sign(&issuer_key, &key_id);
    mandate_vc.verify(&issuer_key.verifying_key()).unwrap();
    println!("  VC issued and signed for mandate");

    // Wrap the VC's subject claims into an SD-JWT for selective disclosure
    let mut vc_claims = HashMap::new();
    vc_claims.insert("vc_id".into(), serde_json::json!(mandate_vc.id));
    vc_claims.insert("scope".into(), serde_json::json!("schema:SearchAction"));
    vc_claims.insert("maxBudget".into(), serde_json::json!(500));
    vc_claims.insert("agent_did".into(), serde_json::json!(agent_did));

    let mut vc_sd_jwt = SelectiveDisclosureJwt::new(issuer_did.clone(), vc_claims);
    vc_sd_jwt.sign(&issuer_key);

    // Agent only needs scope — budget and agent DID stay hidden
    let scope_only = vc_sd_jwt.disclose(&["scope"]).unwrap();
    vc_sd_jwt
        .verify_disclosures(&scope_only, &issuer_key.verifying_key())
        .unwrap();
    println!("  SD-JWT wraps VC claims, discloses only 'scope'");
    println!("  Disclosed: scope = {}", scope_only[0].value);
    println!("  Hidden: maxBudget, agent_did, vc_id");
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] W3C VC Data Model 2.0 envelope: context, types, issuer, proof");
    println!("  [x] Ed25519Signature2020 proof with verification method binding");
    println!("  [x] VC sign/verify roundtrip with JSON serialization");
    println!("  [x] Wrong-key verification rejected");
    println!("  [x] SD-JWT: each claim independently disclosable via salt+hash commitment");
    println!("  [x] Zero-disclosure: signature verified without revealing any claims");
    println!("  [x] Partial disclosure: only permitted properties revealed");
    println!("  [x] Full disclosure: all claims verifiable when needed");
    println!("  [x] Tampered value detected (hash commitment mismatch)");
    println!("  [x] Tampered salt detected (hash commitment mismatch)");
    println!("  [x] Nonexistent claim request rejected");
    println!("  [x] VC → SD-JWT pipeline: credential claims wrapped for selective disclosure");
}
