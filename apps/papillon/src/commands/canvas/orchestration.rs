use chrono::Utc;
use serde_json::json;
use tauri::{AppHandle, Emitter, State};

use crate::error::PapillonError;
use crate::state::AppState;
use papillon_shared::{BlockEvent, BlockState, BlockUpdate};

use super::execution::process_prompt;
use super::helpers::maybe_auto_generate_template;
use super::intent::classify_intent;

#[tauri::command]
pub async fn canvas_prompt(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    prompt_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillonError> {
    // Classify intent via federation (NLU agent or LLM classifier).
    // HTTP URLs are still routed deterministically inside classify_intent.
    let (action_type, preferred, query) = classify_intent(&app, &state, &block_id, &text).await;

    // Early-exit for dataset discovery — routes to multi-agent fan-out coordinator
    if action_type == "schema:DatasetAction" {
        return crate::commands::dataset_discovery::canvas_discover_datasets(
            app, state, _canvas_id, prompt_id, block_id, text,
        )
        .await;
    }

    let (schema_type, content, preference_guided, agent_did) = process_prompt(
        &app,
        &state,
        &prompt_id,
        &block_id,
        &action_type,
        &preferred,
        &query,
    )
    .await?;

    // Auto-generate template if none exists for this schema type.
    maybe_auto_generate_template(&state, &schema_type, &content);

    let now = Utc::now().to_rfc3339();
    let mandate_ttl_hours = {
        let cfg = state
            .orchestrator_config
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cfg.mandate_ttl_hours
    };
    let mandate_expires_at =
        Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
    let _ = app.emit(
        "block_resolved",
        BlockEvent {
            block: BlockUpdate {
                id: block_id.clone(),
                prompt_id,
                prompt_text: Some(text),
                state: BlockState::Resolved,
                schema_type: Some(schema_type),
                content: Some(content),
                agent_did: Some(agent_did),
                mandate_expires_at,
                preference_guided,
                created_at: now.clone(),
                updated_at: now,
            },
        },
    );
    Ok(json!({ "status": "ok", "block_id": block_id }))
}

#[tauri::command]
pub async fn canvas_reshape(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillonError> {
    let (action_type, preferred, query) = classify_intent(&app, &state, &block_id, &text).await;
    let (schema_type, content, preference_guided, agent_did) = process_prompt(
        &app,
        &state,
        "",
        &block_id,
        &action_type,
        &preferred,
        &query,
    )
    .await?;

    // Auto-generate template if none exists for this schema type.
    maybe_auto_generate_template(&state, &schema_type, &content);

    let now = Utc::now().to_rfc3339();
    let mandate_ttl_hours = {
        let cfg = state
            .orchestrator_config
            .read()
            .unwrap_or_else(|e| e.into_inner());
        cfg.mandate_ttl_hours
    };
    let mandate_expires_at =
        Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
    let _ = app.emit(
        "block_resolved",
        BlockEvent {
            block: BlockUpdate {
                id: block_id.clone(),
                prompt_id: String::new(),
                prompt_text: Some(text),
                state: BlockState::Resolved,
                schema_type: Some(schema_type),
                content: Some(content),
                agent_did: Some(agent_did),
                mandate_expires_at,
                preference_guided,
                created_at: now.clone(),
                updated_at: now,
            },
        },
    );
    Ok(json!({ "status": "ok", "block_id": block_id }))
}

#[tauri::command]
pub async fn canvas_retry(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    block_id: String,
    original_text: String,
) -> Result<serde_json::Value, PapillonError> {
    if original_text.is_empty() {
        return Err(PapillonError::from(
            "Cannot retry: original prompt text not available",
        ));
    }
    canvas_prompt(
        app,
        state,
        canvas_id,
        format!("retry-{}", block_id),
        block_id,
        original_text,
    )
    .await
}
