use chrono::Utc;
use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;

/// Append a message to a canvas conversation thread.
#[tauri::command]
pub async fn canvas_message_add(
    state: State<'_, AppState>,
    canvas_id: String,
    role: String,
    content: String,
    block_id: Option<String>,
) -> Result<(), PapillonError> {
    let msg = papillon_shared::CanvasMessageRecord {
        id: uuid::Uuid::new_v4().to_string(),
        canvas_id,
        role,
        content,
        block_id,
        created_at: Utc::now().to_rfc3339(),
    };
    state
        .db
        .insert_canvas_message(&msg)
        .map_err(|e| PapillonError::from(e.0))
}

/// Load all messages for the given canvas, ordered by created_at.
#[tauri::command]
pub async fn canvas_messages_load(
    state: State<'_, AppState>,
    canvas_id: String,
) -> Result<Vec<papillon_shared::CanvasMessageRecord>, PapillonError> {
    state
        .db
        .list_canvas_messages(&canvas_id)
        .map_err(|e| PapillonError::from(e.0))
}
