use pap_credential_store::{SqliteVaultStore, Vault};
use tauri::State;

use crate::error::PapillonError;
use crate::state::AppState;

#[tauri::command]
pub fn vault_open(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), PapillonError> {
    let store = SqliteVaultStore::open(&state.vault_path)
        .map_err(|e| PapillonError::from(e.to_string()))?;

    // If the vault file exists but has no header, Vault::open returns VaultNotInitialized.
    // In that case (first run), create a new vault — it starts already unlocked.
    // Otherwise open the existing vault and unlock it with the supplied password.
    let vault = match Vault::open(store) {
        Ok(v) => {
            v.unlock(&password)
                .map_err(|e| PapillonError::from(e.to_string()))?;
            v
        }
        Err(pap_credential_store::VaultError::VaultNotInitialized) => {
            let store2 = SqliteVaultStore::open(&state.vault_path)
                .map_err(|e| PapillonError::from(e.to_string()))?;
            Vault::create(store2, &password)
                .map_err(|e| PapillonError::from(e.to_string()))?
        }
        Err(e) => return Err(PapillonError::from(e.to_string())),
    };

    let mut guard = state
        .vault
        .lock()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    *guard = Some(vault);
    Ok(())
}

#[tauri::command]
pub fn vault_seal(state: State<'_, AppState>) -> Result<(), PapillonError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    *guard = None;
    Ok(())
}

#[tauri::command]
pub fn vault_disclose_for_agent(
    state: State<'_, AppState>,
    credential_name: String,
    _agent_did: String,
) -> Result<String, PapillonError> {
    let guard = state
        .vault
        .lock()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| PapillonError::from("vault is sealed".to_string()))?;
    vault
        .get_credential(&credential_name)
        .map_err(|e| PapillonError::from(e.to_string()))
}

#[tauri::command]
pub fn vault_store_credential(
    state: State<'_, AppState>,
    credential_name: String,
    credential_value: String,
) -> Result<(), PapillonError> {
    let guard = state
        .vault
        .lock()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| PapillonError::from("vault is sealed".to_string()))?;
    vault
        .store_credential(&credential_name, &credential_value)
        .map_err(|e| PapillonError::from(e.to_string()))
}
