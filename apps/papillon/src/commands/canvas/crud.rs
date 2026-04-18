use chrono::Utc;
use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;

/// List all canvases, most recently updated first.
#[tauri::command]
pub async fn canvas_list(
    state: State<'_, AppState>,
) -> Result<Vec<papillon_shared::CanvasRecord>, PapillonError> {
    state
        .db
        .list_canvases()
        .map_err(|e| PapillonError::from(e.0))
}

/// Create a new canvas with the given name and return the new record.
#[tauri::command]
pub async fn canvas_create(
    state: State<'_, AppState>,
    name: String,
) -> Result<papillon_shared::CanvasRecord, PapillonError> {
    let now = Utc::now().to_rfc3339();
    let record = papillon_shared::CanvasRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        created_at: now.clone(),
        updated_at: now,
    };
    state
        .db
        .upsert_canvas(&record)
        .map_err(|e| PapillonError::from(e.0))?;
    Ok(record)
}

/// Delete a canvas and all its blocks and messages.
#[tauri::command]
pub async fn canvas_delete(state: State<'_, AppState>, id: String) -> Result<(), PapillonError> {
    state
        .db
        .delete_canvas(&id)
        .map_err(|e| PapillonError::from(e.0))
}

/// Rename a canvas (update its name and updated_at).
#[tauri::command]
pub async fn canvas_rename(
    state: State<'_, AppState>,
    id: String,
    name: String,
) -> Result<(), PapillonError> {
    // Load the existing canvas to preserve created_at.
    let mut canvases = state
        .db
        .list_canvases()
        .map_err(|e| PapillonError::from(e.0))?;
    let existing = canvases
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| PapillonError::from(format!("Canvas not found: {id}")))?;
    let record = papillon_shared::CanvasRecord {
        id: existing.id.clone(),
        name,
        created_at: existing.created_at.clone(),
        updated_at: Utc::now().to_rfc3339(),
    };
    state
        .db
        .upsert_canvas(&record)
        .map_err(|e| PapillonError::from(e.0))
}
