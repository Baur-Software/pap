use chrono::Utc;
use tauri::{AppHandle, Emitter};

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::{BlockEvent, BlockState, BlockUpdate, CanvasBlock, CanvasBlockRecord};

/// Create a new user-authored note block on a canvas.
#[tauri::command]
pub async fn canvas_create_note(
    state: tauri::State<'_, AppState>,
    canvas_id: String,
    title: String,
    content: String,
) -> Result<CanvasBlock, PapillonError> {
    let block_id = format!("note-{}", uuid::Uuid::new_v4());
    let now = Utc::now().to_rfc3339();
    let content_json = serde_json::json!({
        "@type": "Note",
        "title": title,
        "note_content": content,
    });
    let content_json_str = serde_json::to_string(&content_json).ok();

    let record = CanvasBlockRecord {
        id: block_id.clone(),
        canvas_id: canvas_id.clone(),
        prompt_text: Some(title.clone()),
        schema_type: Some("Note".to_string()),
        content_json: content_json_str,
        block_state: "note".to_string(),
        episode_id: None,
        agent_did: None,
        mandate_expires_at: None,
        preference_guided: false,
        display_order: 9999,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    state.db.upsert_canvas_block(&record)?;

    Ok(CanvasBlock {
        id: block_id.clone(),
        prompt_id: block_id,
        prompt_text: Some(title.clone()),
        state: BlockState::Note { title, content, editing: false },
        schema_type: Some("Note".to_string()),
        content: Some(content_json),
        linked_block_ids: vec![],
        agent_did: None,
        mandate_expires_at: None,
        preference_guided: false,
        auto_expand: false,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Update a user note block's title and content.
#[tauri::command]
pub async fn canvas_update_note(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    canvas_id: String,
    block_id: String,
    title: String,
    content: String,
) -> Result<CanvasBlock, PapillonError> {
    let now = Utc::now().to_rfc3339();
    let content_json = serde_json::json!({
        "@type": "Note",
        "title": title,
        "note_content": content,
    });
    let content_json_str = serde_json::to_string(&content_json).ok();

    let record = CanvasBlockRecord {
        id: block_id.clone(),
        canvas_id,
        prompt_text: Some(title.clone()),
        schema_type: Some("Note".to_string()),
        content_json: content_json_str,
        block_state: "note".to_string(),
        episode_id: None,
        agent_did: None,
        mandate_expires_at: None,
        preference_guided: false,
        display_order: 0,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    state.db.upsert_canvas_block(&record)?;

    let block_update = BlockUpdate {
        id: block_id.clone(),
        prompt_id: block_id.clone(),
        prompt_text: Some(title.clone()),
        state: BlockState::Note { title: title.clone(), content: content.clone(), editing: false },
        schema_type: Some("Note".to_string()),
        content: Some(content_json.clone()),
        agent_did: None,
        mandate_expires_at: None,
        preference_guided: false,
        created_at: now.clone(),
        updated_at: now.clone(),
    };
    let _ = app.emit("block_updated", BlockEvent { block: block_update });

    Ok(CanvasBlock {
        id: block_id.clone(),
        prompt_id: block_id,
        prompt_text: Some(title.clone()),
        state: BlockState::Note { title, content, editing: false },
        schema_type: Some("Note".to_string()),
        content: Some(content_json),
        linked_block_ids: vec![],
        agent_did: None,
        mandate_expires_at: None,
        preference_guided: false,
        auto_expand: false,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Delete a user note block.
#[tauri::command]
pub async fn canvas_delete_note(
    state: tauri::State<'_, AppState>,
    _canvas_id: String,
    block_id: String,
) -> Result<(), PapillonError> {
    state.db.delete_canvas_block(&block_id)?;
    Ok(())
}
