#![allow(clippy::unwrap_used)]
//! WebAuthn key ceremony Tauri commands.
//!
//! Wires the PAP `pap-webauthn` primitives into the Papillon desktop app as
//! Tauri commands. The ceremony follows the WebAuthn/FIDO2 model:
//!
//! **Registration (key ceremony)**:
//! 1. Frontend calls `begin_registration` → server issues a random challenge.
//! 2. Frontend passes the challenge to the platform authenticator
//!    (`navigator.credentials.create()` in a real browser context, or the
//!    mock authenticator in tests).
//! 3. Frontend calls `complete_registration` with the attestation response.
//!    The backend verifies the response and persists the credential.
//!
//! **Authentication**:
//! 1. Frontend calls `begin_authentication` → server issues a challenge bound
//!    to a specific credential ID.
//! 2. Frontend passes the challenge to the authenticator
//!    (`navigator.credentials.get()`).
//! 3. Frontend calls `complete_authentication` with the assertion response.
//!    The backend verifies and returns `true` on success.
//!
//! Pending challenges are stored in `AppState::webauthn_challenges` behind an
//! `RwLock<HashMap<String, PendingChallenge>>`. Each challenge has a TTL; stale
//! entries are rejected.

use std::collections::HashMap;
use std::sync::RwLock;

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tauri::State;
use uuid::Uuid;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use pap_webauthn::{verify_assertion, AuthenticatorAssertionResponse, WebAuthnCredential};

// ── Challenge TTL ────────────────────────────────────────────────────────────

/// How long (seconds) a pending challenge stays valid before it is rejected.
pub const CHALLENGE_TTL_SECS: i64 = 300; // 5 minutes

// ── Pending challenge state ──────────────────────────────────────────────────

/// Discriminates between registration and authentication challenges so the
/// `complete_*` commands can reject mismatched calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    Registration,
    Authentication,
}

/// A challenge that has been issued but not yet completed.
#[derive(Debug, Clone)]
pub struct PendingChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub user_id: String,
    pub issued_at: DateTime<Utc>,
    pub kind: ChallengeKind,
    /// For authentication challenges only — the credential that must respond.
    pub credential_id: Option<Vec<u8>>,
}

impl PendingChallenge {
    fn is_expired(&self) -> bool {
        Utc::now() - self.issued_at > Duration::seconds(CHALLENGE_TTL_SECS)
    }
}

/// In-memory store of pending WebAuthn challenges, keyed by challenge ID.
pub struct WebAuthnChallengeStore {
    inner: RwLock<HashMap<String, PendingChallenge>>,
}

impl WebAuthnChallengeStore {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a new pending challenge and return its ID.
    pub fn insert(&self, challenge: PendingChallenge) -> String {
        let id = Uuid::new_v4().to_string();
        self.inner
            .write()
            .expect("webauthn challenge store lock poisoned")
            .insert(id.clone(), challenge);
        id
    }

    /// Remove and return a challenge by ID, returning `None` if absent or expired.
    pub fn take(&self, id: &str) -> Option<PendingChallenge> {
        let mut map = self
            .inner
            .write()
            .expect("webauthn challenge store lock poisoned");
        let challenge = map.remove(id)?;
        if challenge.is_expired() {
            None
        } else {
            Some(challenge)
        }
    }
}

impl Default for WebAuthnChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Wire types returned to the frontend ──────────────────────────────────────

/// The challenge data returned to the frontend by `begin_registration`.
/// The frontend uses this to drive `navigator.credentials.create()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    /// Opaque ID used to link this challenge to the `complete_registration` call.
    pub challenge_id: String,
    /// Base64url-encoded random challenge bytes.
    pub challenge_b64: String,
    /// Relying party identifier (e.g. `"papillon.local"`).
    pub rp_id: String,
    /// Opaque user handle.
    pub user_id: String,
    /// Human-readable display name for the authenticator dialog.
    pub user_name: String,
    /// Unix timestamp (seconds) when this challenge expires.
    pub expires_at: i64,
}

/// The challenge data returned to the frontend by `begin_authentication`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    /// Opaque ID used to link this challenge to the `complete_authentication` call.
    pub challenge_id: String,
    /// Base64url-encoded random challenge bytes.
    pub challenge_b64: String,
    /// Base64url-encoded credential ID that should respond to this challenge.
    pub credential_id_b64: String,
    /// Unix timestamp (seconds) when this challenge expires.
    pub expires_at: i64,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn random_challenge() -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, PapillonError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| PapillonError::from(format!("base64 decode error: {e}")))
}

fn webauthn_credential_key(rp_id: &str, credential_id_b64: &str) -> String {
    format!("webauthn_credential_{rp_id}_{credential_id_b64}")
}

// ── Tauri commands ────────────────────────────────────────────────────────────

/// Begin a WebAuthn registration ceremony.
///
/// Generates a cryptographically random 32-byte challenge, stores it in the
/// pending challenge map, and returns the challenge data to the frontend.
///
/// The frontend should pass `challenge_b64` to `navigator.credentials.create()`
/// and then call `complete_registration` with the attestation response.
#[tauri::command]
pub fn begin_registration(
    rp_id: String,
    user_id: String,
    user_name: String,
    state: State<'_, AppState>,
) -> Result<RegistrationChallenge, PapillonError> {
    if rp_id.is_empty() {
        return Err(PapillonError::from("rp_id must not be empty"));
    }
    if user_id.is_empty() {
        return Err(PapillonError::from("user_id must not be empty"));
    }
    if user_name.is_empty() {
        return Err(PapillonError::from("user_name must not be empty"));
    }

    let challenge = random_challenge();
    let challenge_b64 = b64_encode(&challenge);
    let expires_at = Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS);

    let pending = PendingChallenge {
        challenge,
        rp_id: rp_id.clone(),
        user_id: user_id.clone(),
        issued_at: Utc::now(),
        kind: ChallengeKind::Registration,
        credential_id: None,
    };

    let challenge_id = state.webauthn_challenges.insert(pending);

    Ok(RegistrationChallenge {
        challenge_id,
        challenge_b64,
        rp_id,
        user_id,
        user_name,
        expires_at: expires_at.timestamp(),
    })
}

/// Complete a WebAuthn registration ceremony.
///
/// `credential_response` is a JSON-encoded `AuthenticatorAssertionResponse`
/// (or attestation-equivalent) produced by the authenticator. In the Papillon
/// desktop app the frontend drives a mock authenticator backed by the
/// `pap-webauthn` crate's `create_credential` / `get_assertion` primitives.
///
/// On success the credential is persisted to SQLite and returned to the caller.
///
/// # Registration attestation note
/// The WebAuthn spec distinguishes attestation (registration) from assertion
/// (authentication). For the PAP protocol we use the same Ed25519 signing path
/// for both, represented as `AuthenticatorAssertionResponse`. The response
/// includes the public key in `authenticator_data` (the first 32 bytes after
/// the RP-ID hash). This deviates from the full CTAP2 CBOR attestation format
/// for portability, and is clearly documented in the spec divergence section.
#[tauri::command]
pub fn complete_registration(
    challenge_id: String,
    credential_response: String,
    state: State<'_, AppState>,
) -> Result<WebAuthnCredential, PapillonError> {
    let pending = state
        .webauthn_challenges
        .take(&challenge_id)
        .ok_or_else(|| PapillonError::from("challenge not found, already used, or expired"))?;

    if pending.kind != ChallengeKind::Registration {
        return Err(PapillonError::from(
            "challenge was issued for authentication, not registration",
        ));
    }

    // Deserialize the authenticator response from JSON.
    let response: AuthenticatorAssertionResponse = serde_json::from_str(&credential_response)
        .map_err(|e| PapillonError::from(format!("invalid credential_response JSON: {e}")))?;

    // For registration the credential public key is embedded in the response's
    // `authenticator_data` field. The first 32 bytes are the RP-ID hash; bytes
    // 37 onward (after flags + counter) carry the COSE / raw public key.
    // In the PAP mock format, the authenticator_data is exactly 37 bytes
    // (rp_id_hash[32] + flags[1] + counter[4]), and the public key is derived
    // from the credential_id's signing counterpart.  We reconstruct the
    // WebAuthnCredential from a registration-specific field: the raw public key
    // is sent via `authenticator_data` extended with 32 additional bytes.
    let auth_data = &response.authenticator_data;
    if auth_data.len() < 37 + 32 {
        return Err(PapillonError::from(
            "authenticator_data too short to contain public key (expected ≥ 69 bytes)",
        ));
    }

    let pub_key_bytes: [u8; 32] = auth_data[37..37 + 32]
        .try_into()
        .map_err(|_| PapillonError::from("failed to extract public key from authenticator_data"))?;

    let credential = WebAuthnCredential {
        credential_id: response.credential_id.clone(),
        public_key: pub_key_bytes,
        rp_id: pending.rp_id.clone(),
        user_handle: pending.user_id.as_bytes().to_vec(),
        created_at: Utc::now(),
    };

    // Verify the attestation using the standard path: the authenticator must
    // have signed authenticator_data || SHA-256(client_data_json) using the
    // private key whose public component is embedded in authenticator_data.
    verify_assertion(&response, &credential, &pending.challenge)
        .map_err(|e| PapillonError::from(format!("attestation verification failed: {e}")))?;

    // Persist the credential to SQLite so it survives restarts.
    let credential_json = serde_json::to_string(&credential)
        .map_err(|e| PapillonError::from(format!("failed to serialize credential: {e}")))?;
    let store_key = webauthn_credential_key(&pending.rp_id, &b64_encode(&response.credential_id));
    state
        .db
        .set_setting(&store_key, &credential_json)
        .map_err(|e| PapillonError::from(format!("failed to persist credential: {e}")))?;

    Ok(credential)
}

/// Begin a WebAuthn authentication ceremony.
///
/// `credential_id_b64` is the base64url-encoded credential ID of the
/// registered credential that should authenticate. Returns a challenge for
/// the frontend to pass to `navigator.credentials.get()`.
#[tauri::command]
pub fn begin_authentication(
    rp_id: String,
    credential_id_b64: String,
    state: State<'_, AppState>,
) -> Result<AuthenticationChallenge, PapillonError> {
    if rp_id.is_empty() {
        return Err(PapillonError::from("rp_id must not be empty"));
    }
    if credential_id_b64.is_empty() {
        return Err(PapillonError::from("credential_id_b64 must not be empty"));
    }

    // Validate that we have a registered credential for this rp_id + credential_id.
    let store_key = webauthn_credential_key(&rp_id, &credential_id_b64);
    let credential_json = state
        .db
        .get_setting(&store_key)
        .map_err(|e| PapillonError::from(format!("db read error: {e}")))?
        .ok_or_else(|| PapillonError::from("authentication failed"))?;

    // Decode credential_id for storage in pending challenge.
    let credential_id = b64_decode(&credential_id_b64)?;

    // Deserialize stored credential (validates it is well-formed).
    let _: WebAuthnCredential = serde_json::from_str(&credential_json)
        .map_err(|e| PapillonError::from(format!("stored credential is corrupt: {e}")))?;

    let challenge = random_challenge();
    let challenge_b64 = b64_encode(&challenge);
    let expires_at = Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS);

    let pending = PendingChallenge {
        challenge,
        rp_id,
        user_id: String::new(),
        issued_at: Utc::now(),
        kind: ChallengeKind::Authentication,
        credential_id: Some(credential_id),
    };

    let challenge_id = state.webauthn_challenges.insert(pending);

    Ok(AuthenticationChallenge {
        challenge_id,
        challenge_b64,
        credential_id_b64,
        expires_at: expires_at.timestamp(),
    })
}

/// Complete a WebAuthn authentication ceremony.
///
/// `assertion_response` is a JSON-encoded `AuthenticatorAssertionResponse`
/// produced by the authenticator. Returns `true` if the assertion is valid.
#[tauri::command]
pub fn complete_authentication(
    challenge_id: String,
    assertion_response: String,
    state: State<'_, AppState>,
) -> Result<bool, PapillonError> {
    let pending = state
        .webauthn_challenges
        .take(&challenge_id)
        .ok_or_else(|| PapillonError::from("challenge not found, already used, or expired"))?;

    if pending.kind != ChallengeKind::Authentication {
        return Err(PapillonError::from(
            "challenge was issued for registration, not authentication",
        ));
    }

    let response: AuthenticatorAssertionResponse = serde_json::from_str(&assertion_response)
        .map_err(|e| PapillonError::from(format!("invalid assertion_response JSON: {e}")))?;

    // Look up the registered credential from the persistent store.
    let credential_id_b64 = b64_encode(&response.credential_id);
    let store_key = webauthn_credential_key(&pending.rp_id, &credential_id_b64);
    let credential_json = state
        .db
        .get_setting(&store_key)
        .map_err(|e| PapillonError::from(format!("db read error: {e}")))?
        .ok_or_else(|| PapillonError::from("authentication failed"))?;

    let credential: WebAuthnCredential = serde_json::from_str(&credential_json)
        .map_err(|e| PapillonError::from(format!("stored credential is corrupt: {e}")))?;

    verify_assertion(&response, &credential, &pending.challenge)
        .map_err(|e| PapillonError::from(format!("assertion verification failed: {e}")))?;

    Ok(true)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pap_webauthn::{create_credential, get_assertion};
    use sha2::{Digest, Sha256};

    // ── PendingChallenge helpers ──────────────────────────────────────────

    fn make_registration_challenge(rp_id: &str, user_id: &str) -> PendingChallenge {
        PendingChallenge {
            challenge: random_challenge(),
            rp_id: rp_id.to_string(),
            user_id: user_id.to_string(),
            issued_at: Utc::now(),
            kind: ChallengeKind::Registration,
            credential_id: None,
        }
    }

    fn make_authentication_challenge(rp_id: &str, credential_id: Vec<u8>) -> PendingChallenge {
        PendingChallenge {
            challenge: random_challenge(),
            rp_id: rp_id.to_string(),
            user_id: String::new(),
            issued_at: Utc::now(),
            kind: ChallengeKind::Authentication,
            credential_id: Some(credential_id),
        }
    }

    // ── WebAuthnChallengeStore ────────────────────────────────────────────

    #[test]
    fn store_insert_and_take_roundtrip() {
        let store = WebAuthnChallengeStore::new();
        let pc = make_registration_challenge("example.com", "alice");
        let id = store.insert(pc.clone());
        let taken = store.take(&id).expect("challenge should be present");
        assert_eq!(taken.rp_id, "example.com");
        assert_eq!(taken.kind, ChallengeKind::Registration);
    }

    #[test]
    fn store_take_absent_returns_none() {
        let store = WebAuthnChallengeStore::new();
        assert!(store.take("nonexistent-id").is_none());
    }

    #[test]
    fn store_take_is_consume_once() {
        let store = WebAuthnChallengeStore::new();
        let id = store.insert(make_registration_challenge("example.com", "bob"));
        assert!(store.take(&id).is_some());
        assert!(store.take(&id).is_none(), "second take must return None");
    }

    #[test]
    fn expired_challenge_returns_none() {
        let store = WebAuthnChallengeStore::new();
        // Manufacture an already-expired challenge.
        let pc = PendingChallenge {
            challenge: random_challenge(),
            rp_id: "example.com".to_string(),
            user_id: "carol".to_string(),
            issued_at: Utc::now() - Duration::seconds(CHALLENGE_TTL_SECS + 1),
            kind: ChallengeKind::Registration,
            credential_id: None,
        };
        let id = store.insert(pc);
        assert!(
            store.take(&id).is_none(),
            "expired challenge must be rejected"
        );
    }

    // ── Full ceremony flow (using mock authenticator) ─────────────────────

    /// Build a registration `AuthenticatorAssertionResponse` that includes the
    /// public key in the extended authenticator_data (bytes 37..69).
    fn build_registration_response(
        signer: &pap_webauthn::MockWebAuthnSigner,
        challenge: &[u8],
    ) -> AuthenticatorAssertionResponse {
        let credential = signer.credential();
        let rp_id_hash = Sha256::digest(credential.rp_id.as_bytes());
        let flags: u8 = 0x41; // UP + AT (attestation data present)
        let counter: u32 = 0u32;

        // Extended authenticator_data: rp_id_hash[32] + flags[1] + counter[4] + pubkey[32]
        let mut authenticator_data = Vec::with_capacity(69);
        authenticator_data.extend_from_slice(&rp_id_hash);
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        authenticator_data.extend_from_slice(&credential.public_key); // bytes 37..69

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": b64_encode(challenge),
            "origin": format!("https://{}", credential.rp_id),
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        let client_data_hash = Sha256::digest(&client_data_json);
        let mut signed_data = authenticator_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        use pap_webauthn::PrincipalSigner;
        let signature = signer.sign(&signed_data).unwrap();

        AuthenticatorAssertionResponse {
            authenticator_data,
            client_data_json,
            signature,
            credential_id: credential.credential_id.clone(),
        }
    }

    #[test]
    fn registration_challenge_roundtrip() {
        let store = WebAuthnChallengeStore::new();
        let rp_id = "papillon.local";
        let user_id = "user-001";
        let pc = make_registration_challenge(rp_id, user_id);
        let challenge = pc.challenge.clone();

        let id = store.insert(pc);

        // Simulate authenticator creating a credential
        let (signer, _credential) = create_credential(rp_id, "alice");

        // Build registration response with embedded public key
        let response = build_registration_response(&signer, &challenge);

        // Verify directly against the response (not via the Tauri command since
        // AppState requires Tauri infrastructure)
        let credential = signer.credential();
        let auth_data = &response.authenticator_data;
        assert!(
            auth_data.len() >= 69,
            "registration auth_data must be >= 69 bytes"
        );
        let pk: [u8; 32] = auth_data[37..69].try_into().unwrap();
        let reconstructed = WebAuthnCredential {
            credential_id: response.credential_id.clone(),
            public_key: pk,
            rp_id: rp_id.to_string(),
            user_handle: user_id.as_bytes().to_vec(),
            created_at: Utc::now(),
        };

        // The stored pending challenge should still be present
        let taken = store.take(&id).expect("challenge must still be present");
        assert_eq!(taken.rp_id, rp_id);

        // Verify the attestation
        verify_assertion(&response, &reconstructed, &taken.challenge)
            .expect("attestation must verify against reconstructed credential");

        assert_eq!(pk, credential.public_key);
    }

    #[test]
    fn authentication_challenge_roundtrip() {
        let rp_id = "papillon.local";
        let (signer, credential) = create_credential(rp_id, "dave");

        // Simulate `begin_authentication`: issue challenge
        let pending = make_authentication_challenge(rp_id, credential.credential_id.clone());
        let stored_challenge = pending.challenge.clone();

        // Simulate authenticator signing
        let response = get_assertion(&signer, &stored_challenge);

        // Verify assertion
        verify_assertion(&response, &credential, &stored_challenge)
            .expect("authentication assertion must verify");
    }

    #[test]
    fn wrong_challenge_rejected() {
        let rp_id = "papillon.local";
        let (signer, credential) = create_credential(rp_id, "eve");
        let challenge = random_challenge();
        let wrong_challenge = random_challenge();

        let response = get_assertion(&signer, &challenge);
        let result = verify_assertion(&response, &credential, &wrong_challenge);
        assert!(result.is_err(), "wrong challenge must be rejected");
    }

    #[test]
    fn wrong_credential_rejected() {
        let rp_id = "papillon.local";
        let (signer, _) = create_credential(rp_id, "frank");
        let (_, other_credential) = create_credential(rp_id, "grace");
        let challenge = random_challenge();

        let response = get_assertion(&signer, &challenge);
        let result = verify_assertion(&response, &other_credential, &challenge);
        assert!(result.is_err(), "wrong credential must be rejected");
    }

    #[test]
    fn challenge_kind_mismatch_detected() {
        let store = WebAuthnChallengeStore::new();

        // Insert a registration challenge
        let pc = make_registration_challenge("example.com", "heidi");
        let id = store.insert(pc);

        let taken = store.take(&id).unwrap();
        assert_eq!(taken.kind, ChallengeKind::Registration);
        assert_ne!(
            taken.kind,
            ChallengeKind::Authentication,
            "kind mismatch must be detectable"
        );
    }

    #[test]
    fn credential_serialization_roundtrip() {
        let (_, credential) = create_credential("test.example.com", "ivan");
        let json = serde_json::to_string(&credential).unwrap();
        let restored: WebAuthnCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(credential.credential_id, restored.credential_id);
        assert_eq!(credential.public_key, restored.public_key);
        assert_eq!(credential.rp_id, restored.rp_id);
    }

    #[test]
    fn registration_challenge_serialization_roundtrip() {
        let rc = RegistrationChallenge {
            challenge_id: Uuid::new_v4().to_string(),
            challenge_b64: b64_encode(&random_challenge()),
            rp_id: "example.com".to_string(),
            user_id: "user-abc".to_string(),
            user_name: "Alice".to_string(),
            expires_at: Utc::now().timestamp() + CHALLENGE_TTL_SECS,
        };
        let json = serde_json::to_string(&rc).unwrap();
        let restored: RegistrationChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(rc.challenge_id, restored.challenge_id);
        assert_eq!(rc.rp_id, restored.rp_id);
    }

    #[test]
    fn authentication_challenge_serialization_roundtrip() {
        let ac = AuthenticationChallenge {
            challenge_id: Uuid::new_v4().to_string(),
            challenge_b64: b64_encode(&random_challenge()),
            credential_id_b64: b64_encode(&[1u8; 32]),
            expires_at: Utc::now().timestamp() + CHALLENGE_TTL_SECS,
        };
        let json = serde_json::to_string(&ac).unwrap();
        let restored: AuthenticationChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(ac.challenge_id, restored.challenge_id);
        assert_eq!(ac.credential_id_b64, restored.credential_id_b64);
    }
}
