#![allow(clippy::unwrap_used)]
use base64::Engine;
use pap_did::PrincipalKeypair;
use pap_webauthn::{PrincipalSigner, SoftwareSigner};
use papillon_shared::{IdentityInfo, ProfileMetadata};
use tauri::State;
use zeroize::Zeroizing;

use crate::error::PapillonError;
use crate::state::AppState;

/// List all profiles.
#[tauri::command]
pub async fn list_profiles(
    state: State<'_, AppState>,
) -> Result<Vec<ProfileMetadata>, PapillonError> {
    let profiles = state.profiles.read().unwrap_or_else(|e| e.into_inner()).clone();
    Ok(profiles)
}

/// Create a new profile with the given name.
/// Generates a new Ed25519 keypair and stores it in profiles.db.
/// Does NOT automatically switch to the new profile.
#[tauri::command]
pub async fn create_profile(
    state: State<'_, AppState>,
    name: String,
) -> Result<ProfileMetadata, PapillonError> {
    // Generate new keypair
    let keypair = PrincipalKeypair::generate();
    let seed = keypair.signing_key().to_bytes();
    let seed_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);

    // Create profile ID
    let profile_id = uuid::Uuid::new_v4().to_string();

    // Store in profiles database
    let profile_metadata = state
        .profiles_db
        .create_profile(&profile_id, &name, &seed_b64)?;

    // Update in-memory profiles list
    state
        .profiles
        .write()
        .unwrap()
        .push(profile_metadata.clone());

    Ok(profile_metadata)
}

/// Switch to a different profile.
/// CRITICAL: This mutates AppState with the new profile's identity.
/// Returns new IdentityInfo — if the DID changes, frontend must reset all state.
#[tauri::command]
pub async fn switch_profile(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<IdentityInfo, PapillonError> {
    // Verify profile exists
    let profile = state
        .profiles_db
        .get_profile(&profile_id)?
        .ok_or_else(|| PapillonError::from(format!("Profile {profile_id} not found")))?;

    // Load seed from profiles database
    let seed_b64 = state
        .profiles_db
        .get_profile_seed(&profile_id)?
        .ok_or_else(|| PapillonError::from(format!("No seed found for profile {profile_id}")))?;

    // Decode seed
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&seed_b64)
        .map_err(|e| PapillonError::from(format!("Failed to decode seed: {e}")))?;

    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PapillonError::from("Invalid seed length"))?;

    // Recreate keypair and signer
    let keypair = PrincipalKeypair::from_bytes(&seed)
        .map_err(|e| PapillonError::from(format!("Failed to recreate keypair: {e}")))?;

    // Extract public key before consuming keypair into signer
    let pub_key_bytes = keypair.verifying_key().to_bytes();
    let public_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key_bytes);

    let signer = SoftwareSigner::from_keypair(keypair);
    let did = signer.did();

    // Update AppState atomically
    {
        let mut active_id = state.active_profile_id.write().unwrap_or_else(|e| e.into_inner());
        *active_id = profile_id.clone();
    }

    {
        let mut seed_guard = state.principal_seed.write().unwrap_or_else(|e| e.into_inner());
        *seed_guard = Some(Zeroizing::new(seed));
    }

    {
        let mut signer_guard = state.signer.write().unwrap_or_else(|e| e.into_inner());
        *signer_guard = Some(Box::new(signer));
    }

    // Clear registries cache so they reload for the new profile
    {
        let mut registries = state.registries.write().unwrap_or_else(|e| e.into_inner());
        registries.clear();
    }

    // Update profiles database: mark this as active
    state.profiles_db.switch_profile(&profile_id)?;

    // Update in-memory profiles list
    {
        let mut profiles = state.profiles.write().unwrap_or_else(|e| e.into_inner());
        for p in profiles.iter_mut() {
            p.active = p.id == profile_id;
        }
    }

    // Return new identity info
    Ok(IdentityInfo {
        did,
        public_key_b64,
        created_at: profile.created_at,
    })
}

/// Rename a profile.
#[tauri::command]
pub async fn rename_profile(
    state: State<'_, AppState>,
    profile_id: String,
    new_name: String,
) -> Result<ProfileMetadata, PapillonError> {
    // Update in database
    state.profiles_db.rename_profile(&profile_id, &new_name)?;

    // Update in-memory list
    {
        let mut profiles = state.profiles.write().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = profiles.iter_mut().find(|p| p.id == profile_id) {
            p.name = new_name;
        }
    }

    // Return updated profile
    state
        .profiles_db
        .get_profile(&profile_id)?
        .ok_or_else(|| PapillonError::from(format!("Profile {profile_id} not found after rename")))
}

/// Delete a profile.
/// Prevents deletion if it's the last profile or currently active.
#[tauri::command]
pub async fn delete_profile(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<(), PapillonError> {
    // Delete from database (includes safety checks)
    state.profiles_db.delete_profile(&profile_id)?;

    // Update in-memory list
    {
        let mut profiles = state.profiles.write().unwrap_or_else(|e| e.into_inner());
        profiles.retain(|p| p.id != profile_id);
    }

    Ok(())
}

/// Export a profile's seed (with backup confirmation).
/// Used for key backup/export flows.
#[tauri::command]
pub async fn export_profile_seed(
    state: State<'_, AppState>,
    profile_id: String,
) -> Result<String, PapillonError> {
    let seed_b64 = state
        .profiles_db
        .get_profile_seed(&profile_id)?
        .ok_or_else(|| PapillonError::from(format!("No seed found for profile {profile_id}")))?;

    // Mark key as backed up
    {
        let mut backed_up = state.key_backed_up.write().unwrap_or_else(|e| e.into_inner());
        *backed_up = true;
    }

    Ok(seed_b64)
}

/// Import a seed as a new profile.
/// Used for key restore/import flows.
#[tauri::command]
pub async fn import_profile_seed(
    state: State<'_, AppState>,
    name: String,
    seed_b64: String,
) -> Result<ProfileMetadata, PapillonError> {
    // Validate seed format
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&seed_b64)
        .map_err(|e| PapillonError::from(format!("Invalid seed encoding: {e}")))?;

    if bytes.len() != 32 {
        return Err(PapillonError::from(format!(
            "Invalid seed length: {} (expected 32)",
            bytes.len()
        )));
    }

    // Verify it's a valid seed by recreating keypair
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PapillonError::from("Failed to convert seed bytes"))?;

    PrincipalKeypair::from_bytes(&seed)
        .map_err(|e| PapillonError::from(format!("Invalid seed: {e}")))?;

    // Create profile
    let profile_id = uuid::Uuid::new_v4().to_string();
    let profile_metadata = state
        .profiles_db
        .create_profile(&profile_id, &name, &seed_b64)?;

    // Update in-memory profiles list
    state
        .profiles
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .push(profile_metadata.clone());

    // Mark key as backed up (since we're importing it)
    {
        let mut backed_up = state.key_backed_up.write().unwrap_or_else(|e| e.into_inner());
        *backed_up = true;
    }

    Ok(profile_metadata)
}

#[cfg(test)]
mod tests {
    // Integration tests are better run with a full Tauri app context
    // Unit tests here would need mocking, which Tauri's State doesn't support well
    // See: end-to-end tests in frontend instead
}
