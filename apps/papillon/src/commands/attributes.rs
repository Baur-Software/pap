use std::collections::HashMap;

use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;

/// Return all stored principal attributes as a flat key→value map.
/// Keys are exact schema.org vocab strings (e.g. `"schema:givenName"`).
/// The frontend uses this to pre-fill the AwaitingApproval disclosure form.
#[tauri::command]
pub fn get_principal_attributes(
    state: State<'_, AppState>,
) -> Result<HashMap<String, String>, PapillonError> {
    state
        .db
        .get_all_principal_attributes()
        .map_err(|e| PapillonError::from(e.to_string()))
}
