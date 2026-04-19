use chrono::Utc;
use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;

/// Create a new block in the given canvas at the specified display order.
#[tauri::command]
pub async fn canvas_block_create(
    state: State<'_, AppState>,
    canvas_id: String,
    block_id: String,
    prompt_text: Option<String>,
    display_order: i64,
) -> Result<(), PapillonError> {
    let now = Utc::now().to_rfc3339();
    let record = papillon_shared::CanvasBlockRecord {
        id: block_id,
        canvas_id,
        prompt_text,
        schema_type: None,
        content_json: None,
        block_state: "resolving".to_string(),
        episode_id: None,
        agent_did: None,
        mandate_expires_at: None,
        preference_guided: false,
        display_order,
        created_at: now.clone(),
        updated_at: now,
    };
    state
        .db
        .upsert_canvas_block(&record)
        .map_err(|e| PapillonError::from(e.0))
}

/// Update a block to the "resolved" state with result data.
#[tauri::command]
pub async fn canvas_block_resolve(
    state: State<'_, AppState>,
    block_id: String,
    schema_type: String,
    content_json: String,
    episode_id: Option<String>,
    agent_did: Option<String>,
    mandate_expires_at: Option<String>,
) -> Result<(), PapillonError> {
    // Load existing block to preserve immutable fields.
    let blocks = state.db.list_canvas_blocks("").unwrap_or_default();
    // We need to load by iterating all canvases — use a direct lookup approach.
    // Since we need the canvas_id, load the block from all canvases by scanning.
    // Alternatively, do a targeted upsert using the block_id as primary key.
    // The DB upsert_canvas_block is an UPSERT so we can supply a sentinel canvas_id
    // and only update the fields we care about. Instead, fetch the current block first.
    let _ = blocks; // unused — we use a different approach below

    // Build the updated record. We need canvas_id — load by scanning blocks.
    // Since blocks are keyed by block_id, we look for it across all canvases.
    let all_canvases = state
        .db
        .list_canvases()
        .map_err(|e| PapillonError::from(e.0))?;
    let mut found_block: Option<papillon_shared::CanvasBlockRecord> = None;
    for canvas in &all_canvases {
        let canvas_blocks = state
            .db
            .list_canvas_blocks(&canvas.id)
            .map_err(|e| PapillonError::from(e.0))?;
        if let Some(b) = canvas_blocks.into_iter().find(|b| b.id == block_id) {
            found_block = Some(b);
            break;
        }
    }
    let existing =
        found_block.ok_or_else(|| PapillonError::from(format!("Block not found: {block_id}")))?;
    let updated = papillon_shared::CanvasBlockRecord {
        schema_type: Some(schema_type),
        content_json: Some(content_json),
        block_state: "resolved".to_string(),
        episode_id,
        agent_did,
        mandate_expires_at,
        updated_at: Utc::now().to_rfc3339(),
        ..existing
    };
    state
        .db
        .upsert_canvas_block(&updated)
        .map_err(|e| PapillonError::from(e.0))
}

/// Mark a block as failed, storing the failure reason in content_json.
#[tauri::command]
pub async fn canvas_block_fail(
    state: State<'_, AppState>,
    block_id: String,
    reason: String,
) -> Result<(), PapillonError> {
    let all_canvases = state
        .db
        .list_canvases()
        .map_err(|e| PapillonError::from(e.0))?;
    let mut found_block: Option<papillon_shared::CanvasBlockRecord> = None;
    for canvas in &all_canvases {
        let canvas_blocks = state
            .db
            .list_canvas_blocks(&canvas.id)
            .map_err(|e| PapillonError::from(e.0))?;
        if let Some(b) = canvas_blocks.into_iter().find(|b| b.id == block_id) {
            found_block = Some(b);
            break;
        }
    }
    let existing =
        found_block.ok_or_else(|| PapillonError::from(format!("Block not found: {block_id}")))?;
    let updated = papillon_shared::CanvasBlockRecord {
        block_state: "failed".to_string(),
        content_json: Some(serde_json::json!({"reason": reason}).to_string()),
        updated_at: Utc::now().to_rfc3339(),
        ..existing
    };
    state
        .db
        .upsert_canvas_block(&updated)
        .map_err(|e| PapillonError::from(e.0))
}

/// Delete a single canvas block.
#[tauri::command]
pub async fn canvas_block_delete(
    state: State<'_, AppState>,
    block_id: String,
) -> Result<(), PapillonError> {
    state
        .db
        .delete_canvas_block(&block_id)
        .map_err(|e| PapillonError::from(e.0))
}

/// Load all blocks for the given canvas, ordered by display_order.
#[tauri::command]
pub async fn canvas_blocks_load(
    state: State<'_, AppState>,
    canvas_id: String,
) -> Result<Vec<papillon_shared::CanvasBlockRecord>, PapillonError> {
    state
        .db
        .list_canvas_blocks(&canvas_id)
        .map_err(|e| PapillonError::from(e.0))
}
