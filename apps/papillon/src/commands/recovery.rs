use base64::Engine;
use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use pap_core::shamir;
use pap_did::PrincipalKeypair;
use papillon_shared::{
    RecoveryReconstructResult, RecoverySetupResult, RecoveryShardInfo, RecoveryStatus,
};

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
    // Read the current principal seed.
    let seed_lock = state
        .principal_seed
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let seed = seed_lock
        .as_ref()
        .ok_or_else(|| PapillonError::from("No identity — create an identity first"))?;

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

    let (shards, manifest) = shamir::create_shards(&**seed, threshold, total)
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| PapillonError::from(e.to_string()))?;

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
                eprintln!(
                    "[WARN] reconstruct_from_shards: no stored recovery_threshold_m — \
                     threshold-forgery guard skipped (commitment check still active)"
                );
            }
        }
    }

    let shard_refs: Vec<&shamir::RecoveryShard> = shards.iter().collect();
    let seed = shamir::reconstruct(&shard_refs).map_err(|e| PapillonError::from(e.to_string()))?;

    // Derive the keypair from the reconstructed seed.
    let keypair = PrincipalKeypair::from_bytes(&seed)
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let did = keypair.did();
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(keypair.verifying_key().to_bytes());

    // Guard: if an identity is already loaded in AppState, only allow the overwrite
    // if the reconstructed DID matches the current one (i.e., recovering the same identity).
    // This prevents accidental or malicious replacement of an active identity.
    {
        let signer_lock = state
            .signer
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        if let Some(current_signer) = signer_lock.as_ref() {
            let current_did = current_signer.did();
            if current_did != did {
                return Err(PapillonError::from(format!(
                    "reconstructed DID ({did}) does not match the current identity ({current_did}) — \
                     use a different device or explicitly remove your identity before recovering"
                )));
            }
        }
    }

    // Persist the reconstructed seed as the new active identity.
    // seed is Zeroizing<[u8;32]> — encode via deref to avoid copying the raw bytes.
    use pap_webauthn::SoftwareSigner;
    use zeroize::Zeroize;

    let mut seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&*seed);
    state
        .db
        .set_setting("principal_seed_b64", &seed_b64)
        .map_err(|e| PapillonError::from(e.to_string()))?;
    seed_b64.zeroize();

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
    // seed is already Zeroizing<[u8;32]> — move it directly.
    *seed_lock = Some(seed);

    if let Ok(mut backed_up) = state.key_backed_up.write() {
        *backed_up = true;
    }

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
    state
        .db
        .set_setting("recovery_shards_configured", "1")
        .map_err(|e| PapillonError::from(e.to_string()))
}

/// Return whether the principal has previously completed the Shamir recovery ceremony.
#[tauri::command]
pub fn get_recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatus, PapillonError> {
    let configured = state
        .db
        .get_setting("recovery_shards_configured")
        .map_err(|e| PapillonError::from(e.to_string()))?
        .map(|v| v == "1")
        .unwrap_or(false);
    Ok(RecoveryStatus { configured })
}
