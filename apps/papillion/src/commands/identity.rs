use base64::Engine;
use tauri::State;

use crate::error::PapillionError;
use crate::state::AppState;
use papillion_shared::IdentityInfo;

use pap_did::PrincipalKeypair;
use pap_webauthn::SoftwareSigner;

/// Create a new principal identity (generates a new keypair).
#[tauri::command]
pub fn create_identity(state: State<'_, AppState>) -> Result<IdentityInfo, PapillionError> {
    let keypair = PrincipalKeypair::generate();
    let did = keypair.did();
    let pub_key_bytes = keypair.verifying_key().to_bytes();
    let pub_key_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key_bytes);
    let signer = SoftwareSigner::from_keypair(keypair);

    let info = IdentityInfo {
        did: did.clone(),
        public_key_b64: pub_key_b64,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let mut signer_lock = state
        .signer
        .write()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    *signer_lock = Some(Box::new(signer));

    Ok(info)
}

/// Get the current principal identity, if one exists.
#[tauri::command]
pub fn get_identity(state: State<'_, AppState>) -> Result<Option<IdentityInfo>, PapillionError> {
    let signer_lock = state
        .signer
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

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
