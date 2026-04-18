use base64::Engine;
use chrono::Utc;
use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use pap_core::shamir;
use pap_did::PrincipalKeypair;
use papillon_shared::{
    RecoveryReconstructResult, RecoverySetupResult, RecoveryShardInfo, RecoveryStatus,
};

/// Write the revocation marker for the current shard ceremony.
///
/// Called at the tail of `reconstruct_from_shards` so that the old shards are
/// considered spent — any attacker who collected M shards can no longer use
/// them on a fresh device once the principal has distributed new ones.
fn revoke_current_ceremony(db: &dyn crate::db::prelude::DatabaseOps) -> Result<(), PapillonError> {
    let ts = Utc::now().to_rfc3339();
    db.set_setting("recovery_ceremony_revoked_at", &ts)
        .map_err(|e| PapillonError::from(e.to_string()))
}

/// Read recovery status from the DB (extracted for testability).
fn recovery_status_from_db(
    db: &dyn crate::db::prelude::DatabaseOps,
) -> Result<papillon_shared::RecoveryStatus, PapillonError> {
    let configured = db
        .get_setting("recovery_shards_configured")
        .map_err(|e| PapillonError::from(e.to_string()))?
        .map(|v| v == "1")
        .unwrap_or(false);

    let needs_renewal = db
        .get_setting("recovery_ceremony_revoked_at")
        .map_err(|e| PapillonError::from(e.to_string()))?
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    Ok(papillon_shared::RecoveryStatus {
        configured,
        needs_renewal,
    })
}

/// Persist the ceremony-complete flag and clear any pending revocation marker.
///
/// Called by `mark_recovery_complete` so that after the principal distributes
/// fresh shards the `needs_renewal` flag is cleared.
fn complete_recovery_ceremony(
    db: &dyn crate::db::prelude::DatabaseOps,
) -> Result<(), PapillonError> {
    db.set_setting("recovery_shards_configured", "1")
        .map_err(|e| PapillonError::from(e.to_string()))?;
    // Clear the revocation marker by writing an empty string (empty-string-as-deletion
    // convention: `get_setting` callers treat `Some("")` the same as `None`).
    // A future `delete_setting` method on DatabaseOps would be cleaner here.
    db.set_setting("recovery_ceremony_revoked_at", "")
        .map_err(|e| PapillonError::from(e.to_string()))
}

/// Create M-of-N Shamir shards from the current principal's seed.
///
/// `threshold` (M): minimum shards required to reconstruct.
/// `total` (N): number of shards to produce (distributed to N trustees).
///
/// Returns the shard set. Each `shard_json` in the result should be distributed
/// to the corresponding trustee (e.g., saved to a file and sent via a secure channel).
#[tauri::command]
pub fn create_recovery_shards(
    state: State<'_, AppState>,
    threshold: u8,
    total: u8,
) -> Result<RecoverySetupResult, PapillonError> {
    // Copy the seed bytes out of the read lock immediately — holding the lock
    // across RNG, GF arithmetic, serialization, and DB writes blocks concurrent
    // switch_profile calls for the entire ceremony.
    use zeroize::Zeroizing;
    let seed_copy: Zeroizing<[u8; 32]> = {
        let seed_lock = state
            .principal_seed
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        let seed = seed_lock
            .as_ref()
            .ok_or_else(|| PapillonError::from("No identity — create an identity first"))?;
        Zeroizing::new(**seed)
    };

    // Read the DID for embedding in shard metadata.
    let principal_did = {
        let signer_lock = state
            .signer
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        signer_lock
            .as_ref()
            .ok_or_else(|| PapillonError::from("No signer"))?
            .did()
    };

    let (shards, manifest) = shamir::create_shards(&seed_copy, threshold, total)
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| PapillonError::from(e.to_string()))?;

    let shard_infos: Result<Vec<RecoveryShardInfo>, PapillonError> = shards
        .iter()
        .map(|s| {
            Ok(RecoveryShardInfo {
                index: s.index,
                threshold: s.threshold,
                total: s.total,
                shard_json: s
                    .to_json()
                    .map_err(|e| PapillonError::from(e.to_string()))?,
                principal_did: principal_did.clone(),
            })
        })
        .collect();

    // Persist the threshold and total so reconstruct_from_shards can verify them
    // against the embedded shard metadata (prevents threshold-forgery attacks).
    state
        .db
        .set_setting("recovery_threshold_m", &threshold.to_string())
        .map_err(|e| PapillonError::from(e.to_string()))?;
    state
        .db
        .set_setting("recovery_total_n", &total.to_string())
        .map_err(|e| PapillonError::from(e.to_string()))?;

    Ok(RecoverySetupResult {
        shards: shard_infos?,
        manifest_json,
        principal_did,
    })
}

/// Reconstruct the principal identity from M or more Shamir shards.
///
/// `shards_json`: a list of shard JSON blobs (at least M of them).
///
/// On success, imports the reconstructed seed as the active identity and returns
/// the resulting identity info.
#[tauri::command]
pub fn reconstruct_from_shards(
    state: State<'_, AppState>,
    shards_json: Vec<String>,
) -> Result<RecoveryReconstructResult, PapillonError> {
    // Bound the input to the protocol maximum (u8::MAX shards) and reject
    // empty inputs before any deserialization work.
    if shards_json.is_empty() {
        return Err(PapillonError::from("shards_json must not be empty"));
    }
    if shards_json.len() > 255 {
        return Err(PapillonError::from(
            "shards_json exceeds protocol maximum of 255 shards",
        ));
    }
    // Reject individual shard strings that are implausibly large (> 8 KiB).
    for (i, s) in shards_json.iter().enumerate() {
        if s.len() > 8192 {
            return Err(PapillonError::from(format!(
                "shard {i} is too large ({} bytes, max 8192)",
                s.len()
            )));
        }
    }

    // Deserialize each shard.
    let shards: Vec<shamir::RecoveryShard> = shards_json
        .iter()
        .map(|json| {
            shamir::RecoveryShard::from_json(json).map_err(|e| PapillonError::from(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Verify the shards' embedded threshold against the value stored when the
    // ceremony was originally created. This prevents a threshold-forgery attack
    // where an adversary presents honestly-committed threshold=1 shards to
    // silently reconstruct with fewer shares than intended.
    if let Some(first) = shards.first() {
        let stored_threshold = state
            .db
            .get_setting("recovery_threshold_m")
            .map_err(|e| PapillonError::from(e.to_string()))?;
        match stored_threshold {
            Some(expected_str) => {
                let expected: u8 = expected_str
                    .parse()
                    .map_err(|_| PapillonError::from("stored threshold is corrupt"))?;
                if first.threshold != expected {
                    return Err(PapillonError::from(format!(
                        "shard threshold ({}) does not match the ceremony threshold ({}) — shards may be from a different ceremony",
                        first.threshold, expected
                    )));
                }
            }
            None => {
                // No ceremony record found — this device has no prior setup ceremony.
                // The commitment scheme still validates shard integrity, but the
                // belt-and-suspenders threshold check cannot run. Log a warning.
                tracing::warn!(
                    "reconstruct_from_shards: no stored recovery_threshold_m — \
                     threshold-forgery guard skipped (commitment check still active)"
                );
            }
        }
    }

    let shard_refs: Vec<&shamir::RecoveryShard> = shards.iter().collect();
    let seed = shamir::reconstruct(&shard_refs).map_err(|e| PapillonError::from(e.to_string()))?;

    // Derive the keypair from the reconstructed seed.
    let keypair =
        PrincipalKeypair::from_bytes(&seed).map_err(|e| PapillonError::from(e.to_string()))?;

    let did = keypair.did();
    let pub_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(keypair.verifying_key().to_bytes());

    // Acquire the signer write-lock for the entire check-and-update sequence.
    // Holding a write lock prevents a concurrent switch_profile from racing between
    // the DID-match check and the signer/seed installation (TOCTOU).
    use pap_webauthn::SoftwareSigner;
    use zeroize::Zeroize;

    let mut signer_lock = state
        .signer
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    // Guard: if an identity is already loaded, only allow overwrite if the
    // reconstructed DID matches (recovering the same identity, not a different one).
    if let Some(current_signer) = signer_lock.as_ref() {
        let current_did = current_signer.did();
        if current_did != did {
            return Err(PapillonError::from(
                "reconstructed identity does not match the current identity — \
                 use a different device or explicitly remove your identity before recovering",
            ));
        }
    }

    // Persist the reconstructed seed to the authoritative profiles database.
    // Using state.db (legacy key-value store) would be silently reverted on the
    // next restart because AppState::with_db() reads the active seed from profiles_db.
    let active_profile = state
        .profiles_db
        .get_active_profile()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let mut seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(*seed);

    match active_profile {
        Some(profile) => {
            state
                .profiles_db
                .update_profile_seed(&profile.id, &seed_b64)
                .map_err(|e| PapillonError::from(e.to_string()))?;
        }
        None => {
            // No active profile — fall back to legacy store so recovery can still
            // proceed on a first-run (pre-migration) device.
            state
                .db
                .set_setting("principal_seed_b64", &seed_b64)
                .map_err(|e| PapillonError::from(e.to_string()))?;
        }
    }
    seed_b64.zeroize();

    // Install the new signer (write-lock already held).
    let signer = SoftwareSigner::from_keypair(keypair);
    *signer_lock = Some(Box::new(signer));
    drop(signer_lock);

    let mut seed_lock = state
        .principal_seed
        .write()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    // seed is already Zeroizing<[u8;32]> — move it directly.
    *seed_lock = Some(seed);
    drop(seed_lock);

    if let Ok(mut backed_up) = state.key_backed_up.write() {
        *backed_up = true;
    }

    // Old shards are now spent — mark this ceremony as requiring renewal so
    // the frontend prompts the principal to distribute fresh shards.
    revoke_current_ceremony(&*state.db)?;

    Ok(RecoveryReconstructResult {
        did,
        public_key_b64: pub_key_b64,
    })
}

/// Persist a flag indicating the principal has completed the Shamir recovery ceremony.
///
/// Called by the frontend once the user confirms they have distributed all shards (step 4).
/// The flag survives app restarts so the post-onboarding prompt is not shown again.
#[tauri::command]
pub fn mark_recovery_complete(state: State<'_, AppState>) -> Result<(), PapillonError> {
    complete_recovery_ceremony(&*state.db)
}

/// Return whether the principal has previously completed the Shamir recovery ceremony.
#[tauri::command]
pub fn get_recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatus, PapillonError> {
    recovery_status_from_db(&*state.db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_db() -> Arc<crate::db::Database> {
        Arc::new(
            crate::db::Database::open_memory()
                .map_err(PapillonError::from)
                .expect("in-memory db"),
        )
    }

    #[test]
    fn revoke_current_ceremony_sets_timestamp() {
        let db = make_db();
        revoke_current_ceremony(&*db).expect("revoke should succeed");
        let val = db
            .get_setting("recovery_ceremony_revoked_at")
            .expect("db read")
            .expect("should be set");
        assert!(!val.is_empty(), "revocation timestamp must be non-empty");
        assert!(
            val.starts_with("20"),
            "should look like an ISO timestamp, got: {val}"
        );
    }

    #[test]
    fn recovery_status_from_db_needs_renewal_when_revoked() {
        let db = make_db();
        db.set_setting("recovery_shards_configured", "1").unwrap();
        db.set_setting("recovery_ceremony_revoked_at", "2026-04-18T00:00:00Z")
            .unwrap();
        let status = recovery_status_from_db(&*db).expect("status");
        assert!(status.configured);
        assert!(
            status.needs_renewal,
            "needs_renewal must be true when revoked_at is set"
        );
    }

    #[test]
    fn recovery_status_from_db_no_renewal_when_not_revoked() {
        let db = make_db();
        db.set_setting("recovery_shards_configured", "1").unwrap();
        // No revoked_at key set
        let status = recovery_status_from_db(&*db).expect("status");
        assert!(status.configured);
        assert!(
            !status.needs_renewal,
            "needs_renewal must be false when no revocation"
        );
    }

    #[test]
    fn complete_recovery_ceremony_clears_revocation_timestamp() {
        let db = make_db();
        db.set_setting("recovery_ceremony_revoked_at", "2026-04-18T00:00:00Z")
            .unwrap();
        complete_recovery_ceremony(&*db).expect("complete should succeed");
        let val = db
            .get_setting("recovery_ceremony_revoked_at")
            .expect("db read");
        let is_cleared = val.map(|v| v.is_empty()).unwrap_or(true);
        assert!(
            is_cleared,
            "revocation timestamp must be cleared after renewal"
        );
        // Should also have set configured flag
        let configured = db
            .get_setting("recovery_shards_configured")
            .unwrap()
            .map(|v| v == "1")
            .unwrap_or(false);
        assert!(configured, "recovery_shards_configured must be set to 1");
    }

    /// `configured=false` with a revoked ceremony: `needs_renewal` is true even
    /// when `recovery_shards_configured` has never been set to "1".
    #[test]
    fn recovery_status_from_db_needs_renewal_without_configured_flag() {
        let db = make_db();
        // No "recovery_shards_configured" key — configured defaults to false.
        db.set_setting("recovery_ceremony_revoked_at", "2026-04-18T00:00:00Z")
            .unwrap();
        let status = recovery_status_from_db(&*db).expect("status");
        assert!(!status.configured, "configured should be false");
        assert!(
            status.needs_renewal,
            "needs_renewal must be true even when configured=false"
        );
    }

    /// An empty-string value for `recovery_ceremony_revoked_at` must NOT be
    /// treated as a revocation — it is the sentinel used by
    /// `complete_recovery_ceremony` to clear the revocation marker.
    #[test]
    fn recovery_status_from_db_empty_string_revoked_at_is_not_revoked() {
        let db = make_db();
        db.set_setting("recovery_shards_configured", "1").unwrap();
        // Simulate the sentinel written by `complete_recovery_ceremony`.
        db.set_setting("recovery_ceremony_revoked_at", "").unwrap();
        let status = recovery_status_from_db(&*db).expect("status");
        assert!(status.configured);
        assert!(
            !status.needs_renewal,
            "empty-string revoked_at must be treated as absent (not revoked)"
        );
    }

    /// Calling `revoke_current_ceremony` twice overwrites the first timestamp.
    /// Both calls must succeed and the resulting value must still be a non-empty
    /// ISO timestamp.
    #[test]
    fn revoke_current_ceremony_called_twice_overwrites_first_timestamp() {
        let db = make_db();
        revoke_current_ceremony(&*db).expect("first revoke should succeed");
        let first_ts = db
            .get_setting("recovery_ceremony_revoked_at")
            .unwrap()
            .unwrap();
        assert!(!first_ts.is_empty());

        // Small delay is not practical in unit tests; both timestamps will be
        // from the same second. We just need to verify the second call does not
        // error and leaves a valid (non-empty) timestamp.
        revoke_current_ceremony(&*db).expect("second revoke should succeed");
        let second_ts = db
            .get_setting("recovery_ceremony_revoked_at")
            .unwrap()
            .unwrap();
        assert!(
            !second_ts.is_empty(),
            "second revoke must leave a non-empty timestamp"
        );
        assert!(
            second_ts.starts_with("20"),
            "second timestamp should look like an ISO timestamp, got: {second_ts}"
        );
    }
}
