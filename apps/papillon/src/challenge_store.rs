//! Time-bounded nonce store for the principal keypair challenge-response protocol.
//!
//! Before any identity-mutating Tauri command (`create_identity`, `import_key`,
//! `canvas_approve_block`) executes, the frontend must:
//!
//! 1. Call `get_identity_challenge()` → receive a `ChallengeToken` containing a
//!    random nonce and an `expires_at` timestamp.
//! 2. Sign the nonce bytes with the current principal's Ed25519 keypair.
//! 3. Pass a `SignedChallenge { nonce_b64, signature_b64 }` to the mutating
//!    command alongside its other arguments.
//! 4. The command calls `IdentityChallengeStore::take_and_verify()` which:
//!    - Removes the nonce from the store (one-time use).
//!    - Rejects it if it has expired (`CHALLENGE_TTL_SECS`).
//!    - Verifies the Ed25519 signature with `verify_strict`.
//!
//! **First-run exception**: when `create_identity` is called and no principal
//! keypair exists yet, there is nothing to sign with. The command documents this
//! exception and skips verification in that case only.

use std::collections::HashMap;
use std::sync::RwLock;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How long (in seconds) a principal challenge nonce remains valid.
pub const CHALLENGE_TTL_SECS: i64 = 120; // 2 minutes — tight window, large enough for round-trip

// ── Public wire types ────────────────────────────────────────────────────────

/// Returned by `get_identity_challenge` to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeToken {
    /// Opaque ID used to locate the pending nonce on verification.
    pub challenge_id: String,
    /// Base64url-encoded 32-byte random nonce. The frontend signs this.
    pub nonce_b64: String,
    /// Unix timestamp (seconds) after which this challenge is invalid.
    pub expires_at: i64,
}

/// Passed by the frontend to identity-mutating commands.
///
/// `nonce_b64` must match what was returned by `get_identity_challenge`.
/// `signature_b64` is the base64url-encoded Ed25519 signature of the raw nonce
/// bytes (NOT the base64 string) produced by the principal's current keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedChallenge {
    /// The `challenge_id` returned by `get_identity_challenge`.
    pub challenge_id: String,
    /// Base64url-encoded Ed25519 signature over the raw nonce bytes.
    pub signature_b64: String,
}

// ── Internal pending state ───────────────────────────────────────────────────

struct PendingChallenge {
    nonce: Vec<u8>,
    issued_at: DateTime<Utc>,
}

impl PendingChallenge {
    fn is_expired(&self) -> bool {
        Utc::now() - self.issued_at > Duration::seconds(CHALLENGE_TTL_SECS)
    }
}

// ── Challenge store ──────────────────────────────────────────────────────────

/// In-memory store of pending identity challenges.
///
/// Thread-safe via `RwLock<HashMap<…>>`. Entries are one-time use: `take_and_verify`
/// removes the entry before checking the signature, preventing replay attacks.
pub struct IdentityChallengeStore {
    inner: RwLock<HashMap<String, PendingChallenge>>,
}

impl IdentityChallengeStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a fresh nonce, store it, and return a `ChallengeToken`.
    pub fn issue(&self) -> ChallengeToken {
        let mut nonce = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&nonce);

        let id = Uuid::new_v4().to_string();
        let issued_at = Utc::now();
        let expires_at = (issued_at + Duration::seconds(CHALLENGE_TTL_SECS)).timestamp();

        self.inner
            .write()
            .expect("identity challenge store lock poisoned")
            .insert(id.clone(), PendingChallenge { nonce, issued_at });

        ChallengeToken {
            challenge_id: id,
            nonce_b64,
            expires_at,
        }
    }

    /// Remove the pending challenge for `challenge_id`, check TTL, and verify
    /// the Ed25519 `signature_b64` over the nonce bytes against `verifying_key`.
    ///
    /// Returns `Ok(())` on success. Returns `Err` with a descriptive message on:
    /// - Unknown or already-used challenge ID.
    /// - Expired nonce.
    /// - Base64 decode failure.
    /// - Invalid or wrong-key signature.
    pub fn take_and_verify(
        &self,
        signed: &SignedChallenge,
        verifying_key: &VerifyingKey,
    ) -> Result<(), String> {
        // Remove first — prevents replay even if verification fails.
        let pending = self
            .inner
            .write()
            .expect("identity challenge store lock poisoned")
            .remove(&signed.challenge_id)
            .ok_or_else(|| "challenge not found, already used, or expired".to_string())?;

        if pending.is_expired() {
            return Err("challenge expired".to_string());
        }

        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&signed.signature_b64)
            .map_err(|e| format!("invalid signature base64: {e}"))?;

        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "signature must be exactly 64 bytes".to_string())?;

        let signature = Signature::from_bytes(&sig_arr);

        // verify_strict rejects low-order points and enforces prime-order subgroup.
        verifying_key
            .verify_strict(&pending.nonce, &signature)
            .map_err(|_| "signature verification failed — unauthorized caller".to_string())
    }
}

impl Default for IdentityChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Test helpers (cfg(test) only) ────────────────────────────────────────────

#[cfg(test)]
impl IdentityChallengeStore {
    /// Insert a challenge with a custom timestamp — used by tests to simulate expiry.
    pub fn insert_expired_for_test(&self, nonce: Vec<u8>) -> String {
        let id = Uuid::new_v4().to_string();
        self.inner.write().expect("lock poisoned").insert(
            id.clone(),
            PendingChallenge {
                nonce,
                issued_at: Utc::now() - Duration::seconds(CHALLENGE_TTL_SECS + 1),
            },
        );
        id
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn sign_nonce(signing_key: &SigningKey, nonce_b64: &str) -> String {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(nonce_b64)
            .expect("valid nonce_b64 in test");
        let sig = signing_key.sign(&nonce);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    // ── issue ─────────────────────────────────────────────────────────────

    #[test]
    fn issue_returns_unique_ids() {
        let store = IdentityChallengeStore::new();
        let t1 = store.issue();
        let t2 = store.issue();
        assert_ne!(t1.challenge_id, t2.challenge_id, "IDs must be unique");
        assert_ne!(t1.nonce_b64, t2.nonce_b64, "nonces must be unique");
    }

    #[test]
    fn issue_nonce_is_32_bytes() {
        let store = IdentityChallengeStore::new();
        let token = store.issue();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&token.nonce_b64)
            .expect("valid base64");
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn issue_sets_future_expiry() {
        let store = IdentityChallengeStore::new();
        let token = store.issue();
        let now = Utc::now().timestamp();
        assert!(
            token.expires_at > now,
            "expires_at ({}) must be in the future (now={})",
            token.expires_at,
            now
        );
    }

    // ── take_and_verify — happy path ──────────────────────────────────────

    #[test]
    fn valid_challenge_accepted() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();

        let token = store.issue();
        let sig_b64 = sign_nonce(&sk, &token.nonce_b64);

        let signed = SignedChallenge {
            challenge_id: token.challenge_id.clone(),
            signature_b64: sig_b64,
        };

        let result = store.take_and_verify(&signed, &sk.verifying_key());
        assert!(
            result.is_ok(),
            "valid signature must be accepted: {:?}",
            result
        );
    }

    // ── take_and_verify — rejection cases ────────────────────────────────

    #[test]
    fn unknown_challenge_id_rejected() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();

        let signed = SignedChallenge {
            challenge_id: "nonexistent-id".to_string(),
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]),
        };

        let result = store.take_and_verify(&signed, &sk.verifying_key());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("not found"),
            "error must mention not found"
        );
    }

    #[test]
    fn invalid_signature_rejected() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();
        let wrong_sk = make_signing_key(); // different key

        let token = store.issue();
        // Sign with the WRONG key — verifying with sk.verifying_key() must fail.
        let sig_b64 = sign_nonce(&wrong_sk, &token.nonce_b64);

        let signed = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: sig_b64,
        };

        let result = store.take_and_verify(&signed, &sk.verifying_key());
        assert!(result.is_err(), "wrong-key signature must be rejected");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("signature verification failed"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn expired_nonce_rejected() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();

        // Manually insert an expired challenge.
        let nonce = vec![0xde, 0xad, 0xbe, 0xef];
        let id = Uuid::new_v4().to_string();
        {
            let mut map = store.inner.write().unwrap();
            map.insert(
                id.clone(),
                PendingChallenge {
                    nonce: nonce.clone(),
                    // issued CHALLENGE_TTL_SECS + 1 seconds in the past
                    issued_at: Utc::now() - Duration::seconds(CHALLENGE_TTL_SECS + 1),
                },
            );
        }

        let sig = sk.sign(&nonce);
        let signed = SignedChallenge {
            challenge_id: id,
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };

        let result = store.take_and_verify(&signed, &sk.verifying_key());
        assert!(result.is_err(), "expired challenge must be rejected");
        assert!(
            result.unwrap_err().contains("expired"),
            "error must mention expiry"
        );
    }

    #[test]
    fn replay_attack_prevented() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();

        let token = store.issue();
        let sig_b64 = sign_nonce(&sk, &token.nonce_b64);

        let signed = SignedChallenge {
            challenge_id: token.challenge_id.clone(),
            signature_b64: sig_b64.clone(),
        };

        // First use: must succeed.
        store
            .take_and_verify(&signed, &sk.verifying_key())
            .expect("first use must succeed");

        // Second use with the same challenge_id: must fail.
        let signed_again = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: sig_b64,
        };
        let result = store.take_and_verify(&signed_again, &sk.verifying_key());
        assert!(result.is_err(), "replay must be rejected");
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn bad_base64_signature_rejected() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();

        let token = store.issue();

        let signed = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: "!!!not-valid-base64!!!".to_string(),
        };

        let result = store.take_and_verify(&signed, &sk.verifying_key());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("invalid signature base64"),
            "must report base64 error"
        );
    }

    #[test]
    fn wrong_length_signature_rejected() {
        let store = IdentityChallengeStore::new();
        let sk = make_signing_key();

        let token = store.issue();
        // 63 bytes — one short of a valid Ed25519 signature.
        let short_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 63]);

        let signed = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: short_sig,
        };

        let result = store.take_and_verify(&signed, &sk.verifying_key());
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("exactly 64 bytes"),
            "must report wrong length"
        );
    }
}
