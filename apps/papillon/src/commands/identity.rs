use base64::Engine;
use tauri::State;
use zeroize::Zeroizing;

use crate::challenge_store::{ChallengeToken, SignedChallenge};
use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::keypair_store::KeypairStore;
use crate::state::AppState;
use papillon_shared::{ExportedKey, IdentityInfo, KeyBackupStatus, SuccessorDesignation};

use pap_did::PrincipalKeypair;
use pap_webauthn::SoftwareSigner;

/// Issue a time-bounded nonce that the frontend must sign with the principal
/// keypair before calling any identity-mutating command.
///
/// The returned [`ChallengeToken`] contains:
/// - `challenge_id` — opaque identifier; pass this back in [`SignedChallenge`].
/// - `nonce_b64`    — base64url-encoded 32-byte nonce to sign.
/// - `expires_at`   — Unix timestamp (seconds); the challenge is invalid after this.
///
/// The frontend signs the **raw nonce bytes** (not the base64 string) with the
/// principal's Ed25519 keypair and passes a [`SignedChallenge`] to the mutating
/// command.
#[tauri::command]
pub fn get_identity_challenge(state: State<'_, AppState>) -> Result<ChallengeToken, PapillonError> {
    Ok(state.identity_challenges.issue())
}

/// Create a new principal identity (generates a new keypair).
/// Returns error if the new identity cannot be persisted to the database,
/// preventing the frontend from believing the identity was created when it wasn't.
///
/// **Challenge requirement**: If a principal identity already exists,
/// `signed_challenge` must contain a valid [`SignedChallenge`] obtained from
/// [`get_identity_challenge`] and signed with the current principal's keypair.
/// This prevents any frontend code from replacing the principal's identity
/// without cryptographic proof of possession.
///
/// **First-run exception**: When no identity exists yet (`AppState::signer` is
/// `None`), `signed_challenge` may be `None` and verification is skipped — the
/// caller cannot sign a challenge without a keypair.
#[tauri::command]
pub fn create_identity(
    state: State<'_, AppState>,
    signed_challenge: Option<SignedChallenge>,
) -> Result<IdentityInfo, PapillonError> {
    create_identity_inner(&state, signed_challenge)
}

/// Testable inner function for `create_identity`.
pub(crate) fn create_identity_inner(
    state: &AppState,
    signed_challenge: Option<SignedChallenge>,
) -> Result<IdentityInfo, PapillonError> {
    // If a principal identity already exists, require a valid signed challenge.
    {
        let signer_lock = state
            .signer
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        if let Some(signer) = signer_lock.as_ref() {
            // Identity exists — caller must prove possession of the current keypair.
            let sc = signed_challenge.ok_or_else(|| {
                PapillonError::from("signed_challenge required when an identity already exists")
            })?;

            state
                .identity_challenges
                .take_and_verify(&sc, &signer.verifying_key())
                .map_err(|e| PapillonError::from(format!("authorization failed: {e}")))?;
        }
        // else: first run — no keypair exists, challenge verification is skipped.
    }

    let keypair = PrincipalKeypair::generate();
    let did = keypair.did();
    let pub_key_bytes = keypair.verifying_key().to_bytes();
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key_bytes);
    let raw_seed = keypair.signing_key().to_bytes();
    let signer = SoftwareSigner::from_keypair(keypair);

    // Persist the new seed to SQLite BEFORE updating in-memory state.
    // This ensures we don't get into a state where the frontend thinks we
    // succeeded but the seed wasn't actually saved.
    let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_seed);
    state.db.set_setting("principal_seed_b64", &seed_b64)?;

    let mut signer_lock = state
        .signer
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    *signer_lock = Some(Box::new(signer));

    let mut seed_lock = state
        .principal_seed
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    *seed_lock = Some(Zeroizing::new(raw_seed));

    if let Ok(mut backed_up) = state.key_backed_up.write() {
        *backed_up = false;
    }

    Ok(IdentityInfo {
        did: did.clone(),
        public_key_b64: pub_key_b64,
        created_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Get the current principal identity, if one exists.
#[tauri::command]
pub fn get_identity(state: State<'_, AppState>) -> Result<Option<IdentityInfo>, PapillonError> {
    let signer_lock = state
        .signer
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    match signer_lock.as_ref() {
        Some(signer) => {
            let did = signer.did();
            let pub_key_bytes = signer.verifying_key().to_bytes();
            let pub_key_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key_bytes);
            Ok(Some(IdentityInfo {
                did,
                public_key_b64: pub_key_b64,
                created_at: String::new(),
            }))
        }
        None => Ok(None),
    }
}

/// Export the current identity's raw seed as base64url.
#[tauri::command]
pub fn export_key(state: State<'_, AppState>) -> Result<ExportedKey, PapillonError> {
    let seed_lock = state
        .principal_seed
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let seed = seed_lock
        .as_ref()
        .ok_or_else(|| PapillonError::from("No identity to export"))?;

    let signer_lock = state
        .signer
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let did = signer_lock
        .as_ref()
        .ok_or_else(|| PapillonError::from("No identity"))?
        .did();

    let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);

    if let Ok(mut backed_up) = state.key_backed_up.write() {
        *backed_up = true;
    }

    Ok(ExportedKey {
        seed_b64,
        did,
        exported_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Import an identity from a base64url seed, replacing the current one.
/// Returns error if the imported seed cannot be persisted to the database,
/// preventing the frontend from believing the identity was imported when it wasn't.
///
/// **Challenge requirement**: `signed_challenge` must contain a valid
/// [`SignedChallenge`] obtained from [`get_identity_challenge`] and signed with
/// the current principal's keypair. Because Papillon always creates a keypair
/// on first launch, this requirement is always enforced — there is no first-run
/// exception for `import_key`.
#[tauri::command]
pub fn import_key(
    state: State<'_, AppState>,
    seed_b64: String,
    signed_challenge: SignedChallenge,
) -> Result<IdentityInfo, PapillonError> {
    import_key_inner(&state, seed_b64, signed_challenge)
}

/// Testable inner function for `import_key`.
pub(crate) fn import_key_inner(
    state: &AppState,
    seed_b64: String,
    signed_challenge: SignedChallenge,
) -> Result<IdentityInfo, PapillonError> {
    // Always require a valid signed challenge — a keypair is always present
    // after first launch, so there is no first-run exception for import_key.
    {
        let signer_lock = state
            .signer
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;

        let signer = signer_lock
            .as_ref()
            .ok_or_else(|| PapillonError::from("no identity to authorize import against"))?;

        state
            .identity_challenges
            .take_and_verify(&signed_challenge, &signer.verifying_key())
            .map_err(|e| PapillonError::from(format!("authorization failed: {e}")))?;
    }

    let seed_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&seed_b64)
        .map_err(|e| PapillonError::from(format!("Invalid base64url: {e}")))?;

    let seed: [u8; 32] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| PapillonError::from("Seed must be exactly 32 bytes"))?;

    let keypair =
        PrincipalKeypair::from_bytes(&seed).map_err(|e| PapillonError::from(e.to_string()))?;

    // Persist the imported seed to SQLite BEFORE updating in-memory state
    state.db.set_setting("principal_seed_b64", &seed_b64)?;

    let did = keypair.did();
    let pub_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keypair.verifying_key().to_bytes());
    let signer = SoftwareSigner::from_keypair(keypair);

    let mut signer_lock = state
        .signer
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    *signer_lock = Some(Box::new(signer));

    let mut seed_lock = state
        .principal_seed
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    *seed_lock = Some(Zeroizing::new(seed));

    // Persist the imported seed to SQLite
    if let Err(e) = state.db.set_setting("principal_seed_b64", &seed_b64) {
        eprintln!("Failed to persist imported seed: {e}");
    }

    if let Ok(mut backed_up) = state.key_backed_up.write() {
        *backed_up = true;
    }

    Ok(IdentityInfo {
        did,
        public_key_b64: pub_key_b64,
        created_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Check if the key has been backed up.
#[tauri::command]
pub fn get_key_backup_status(state: State<'_, AppState>) -> Result<KeyBackupStatus, PapillonError> {
    let backed_up = state
        .key_backed_up
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    Ok(KeyBackupStatus {
        backed_up: *backed_up,
    })
}

/// Add a successor designation.
#[tauri::command]
pub fn add_successor(
    state: State<'_, AppState>,
    successor_did: String,
    relationship: String,
    notes: String,
) -> Result<Vec<SuccessorDesignation>, PapillonError> {
    let mut successors = state
        .successor_designations
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    successors.push(SuccessorDesignation {
        successor_did,
        relationship,
        notes,
        created_at: chrono::Utc::now().to_rfc3339(),
    });
    Ok(successors.clone())
}

/// List successor designations.
#[tauri::command]
pub fn list_successors(
    state: State<'_, AppState>,
) -> Result<Vec<SuccessorDesignation>, PapillonError> {
    let successors = state
        .successor_designations
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    Ok(successors.clone())
}

/// Remove a successor designation by DID.
#[tauri::command]
pub fn remove_successor(
    state: State<'_, AppState>,
    successor_did: String,
) -> Result<Vec<SuccessorDesignation>, PapillonError> {
    let mut successors = state
        .successor_designations
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    successors.retain(|s| s.successor_did != successor_did);
    Ok(successors.clone())
}

/// Return the `did:key` DID of the persisted principal keypair.
///
/// This DID is stable across app restarts — it is derived from the
/// Ed25519 seed stored in `{app_data_dir}/principal.key`.
#[tauri::command]
pub fn get_principal_did(keypair_store: State<'_, KeypairStore>) -> Result<String, String> {
    Ok(keypair_store.principal_did())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use base64::Engine;
    use ed25519_dalek::Signer;

    use crate::challenge_store::SignedChallenge;
    use crate::state::AppState;

    use super::{create_identity_inner, import_key_inner};

    fn make_app_state() -> AppState {
        // AppState::default() opens temp SQLite files — suitable for unit tests.
        AppState::default()
    }

    /// Sign the raw nonce bytes (decoded from `nonce_b64`) with the given signing key.
    fn sign_nonce(sk: &ed25519_dalek::SigningKey, nonce_b64: &str) -> String {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(nonce_b64)
            .expect("valid nonce in test");
        let sig = sk.sign(&nonce);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    /// Extract the current signing key seed from AppState.
    fn get_signing_key(state: &AppState) -> ed25519_dalek::SigningKey {
        let seed = state.principal_seed.read().unwrap();
        let seed_bytes: &[u8; 32] = seed.as_ref().expect("seed present in test state");
        ed25519_dalek::SigningKey::from_bytes(seed_bytes)
    }

    // ── create_identity — first run (no existing identity) ───────────────

    #[test]
    fn create_identity_first_run_no_challenge_needed() {
        // Wipe the signer/seed so we simulate a true first-run state.
        let state = make_app_state();
        {
            *state.signer.write().unwrap() = None;
            *state.principal_seed.write().unwrap() = None;
        }

        // First run: signed_challenge = None, should succeed.
        let result = create_identity_inner(&state, None);
        assert!(
            result.is_ok(),
            "first run must succeed without challenge: {:?}",
            result
        );
    }

    // ── create_identity — replacement with existing identity ─────────────

    #[test]
    fn create_identity_valid_challenge_accepted() {
        let state = make_app_state();
        let sk = get_signing_key(&state);

        let token = state.identity_challenges.issue();
        let sig_b64 = sign_nonce(&sk, &token.nonce_b64);

        let sc = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: sig_b64,
        };

        let result = create_identity_inner(&state, Some(sc));
        assert!(
            result.is_ok(),
            "valid signed challenge must be accepted: {:?}",
            result
        );
    }

    #[test]
    fn create_identity_missing_challenge_rejected_when_identity_exists() {
        let state = make_app_state();
        // An identity already exists after make_app_state() — no challenge provided.
        let result = create_identity_inner(&state, None);
        assert!(result.is_err(), "missing challenge must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("signed_challenge required"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn create_identity_invalid_signature_rejected() {
        let state = make_app_state();

        let token = state.identity_challenges.issue();
        // Sign with a WRONG key — verification against the principal key must fail.
        let wrong_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sig_b64 = sign_nonce(&wrong_sk, &token.nonce_b64);

        let sc = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: sig_b64,
        };

        let result = create_identity_inner(&state, Some(sc));
        assert!(result.is_err(), "wrong-key signature must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("authorization failed"),
            "unexpected error: {msg}"
        );
    }

    // ── import_key — challenge always required ────────────────────────────

    #[test]
    fn import_key_valid_challenge_accepted() {
        let state = make_app_state();
        let sk = get_signing_key(&state);

        // Generate a fresh seed to import.
        let new_kp = pap_did::PrincipalKeypair::generate();
        let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(new_kp.signing_key().to_bytes());

        let token = state.identity_challenges.issue();
        let sig_b64 = sign_nonce(&sk, &token.nonce_b64);
        let sc = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: sig_b64,
        };

        let result = import_key_inner(&state, seed_b64, sc);
        assert!(
            result.is_ok(),
            "valid challenge must be accepted: {:?}",
            result
        );
    }

    #[test]
    fn import_key_invalid_signature_rejected() {
        let state = make_app_state();

        let new_kp = pap_did::PrincipalKeypair::generate();
        let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(new_kp.signing_key().to_bytes());

        let token = state.identity_challenges.issue();
        let wrong_sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sig_b64 = sign_nonce(&wrong_sk, &token.nonce_b64);
        let sc = SignedChallenge {
            challenge_id: token.challenge_id,
            signature_b64: sig_b64,
        };

        let result = import_key_inner(&state, seed_b64, sc);
        assert!(result.is_err(), "wrong-key signature must be rejected");
    }

    #[test]
    fn import_key_expired_challenge_rejected() {
        let state = make_app_state();
        let sk = get_signing_key(&state);

        // Insert an already-expired challenge using the test helper.
        let nonce = vec![0xca, 0xfe, 0xba, 0xbe];
        let challenge_id = state
            .identity_challenges
            .insert_expired_for_test(nonce.clone());

        let sig = sk.sign(&nonce);
        let sc = SignedChallenge {
            challenge_id,
            signature_b64: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };

        let new_kp = pap_did::PrincipalKeypair::generate();
        let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(new_kp.signing_key().to_bytes());

        let result = import_key_inner(&state, seed_b64, sc);
        assert!(result.is_err(), "expired challenge must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("expired"), "error must mention expiry: {msg}");
    }
}
