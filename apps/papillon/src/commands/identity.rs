use base64::Engine;
use tauri::State;
use zeroize::Zeroizing;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::{ExportedKey, IdentityInfo, KeyBackupStatus, SuccessorDesignation};

use pap_did::PrincipalKeypair;
use pap_webauthn::SoftwareSigner;

/// Create a new principal identity (generates a new keypair).
/// Returns error if the new identity cannot be persisted to the database,
/// preventing the frontend from believing the identity was created when it wasn't.
#[tauri::command]
pub fn create_identity(state: State<'_, AppState>) -> Result<IdentityInfo, PapillonError> {
    let keypair = PrincipalKeypair::generate();
    let did = keypair.did();
    let pub_key_bytes = keypair.verifying_key().to_bytes();
    let pub_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key_bytes);
    let raw_seed = keypair.signing_key().to_bytes();
    let signer = SoftwareSigner::from_keypair(keypair);

    // Persist the new seed to SQLite BEFORE updating in-memory state
    // This ensures we don't get into a state where the frontend thinks we succeeded
    // but the seed wasn't actually saved.
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

    // Persist the new seed to SQLite
    let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw_seed);
    if let Err(e) = state.db.set_setting("principal_seed_b64", &seed_b64) {
        eprintln!("Failed to persist principal seed: {e}");
    }

    if let Ok(mut backed_up) = state.key_backed_up.write() {
        *backed_up = false;
    }

    let info = IdentityInfo {
        did: did.clone(),
        public_key_b64: pub_key_b64,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    Ok(info)
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
#[tauri::command]
pub fn import_key(
    state: State<'_, AppState>,
    seed_b64: String,
) -> Result<IdentityInfo, PapillonError> {
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
