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

    let shard_refs: Vec<&shamir::RecoveryShard> = shards.iter().collect();
    let seed = shamir::reconstruct(&shard_refs).map_err(|e| PapillonError::from(e.to_string()))?;

    // Derive the keypair from the reconstructed seed.
    let keypair = PrincipalKeypair::from_bytes(&seed)
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let did = keypair.did();
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(keypair.verifying_key().to_bytes());

    // Persist the reconstructed seed as the new active identity.
    let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
    state
        .db
        .set_setting("principal_seed_b64", &seed_b64)
        .map_err(|e| PapillonError::from(e.to_string()))?;

    use pap_webauthn::SoftwareSigner;
    use zeroize::Zeroizing;

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
