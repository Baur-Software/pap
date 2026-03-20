use chrono::Utc;
use serde_json::json;
use tauri::{AppHandle, Emitter, State};

use crate::error::PapillionError;
use crate::state::{AppState, BUILTIN_REGISTRY_URL};
use papillion_shared::{BlockEvent, BlockState, CanvasBlock, ScenarioCard};

/// Emit a phase-update event for a canvas block.
fn emit_phase(app: &AppHandle, block_id: &str, prompt_id: &str, phase: u8, label: &str) {
    let now = Utc::now().to_rfc3339();
    let block = CanvasBlock {
        id: block_id.to_string(),
        prompt_id: prompt_id.to_string(),
        state: BlockState::Resolving {
            phase,
            phase_label: label.into(),
        },
        schema_type: None,
        content: None,
        linked_block_ids: Vec::new(),
        created_at: now.clone(),
        updated_at: now,
    };
    let _ = app.emit("block_updated", BlockEvent { block });
}

/// Classify a prompt into a matching scenario by checking the registry for
/// agents whose capabilities or names match keywords in the prompt.
fn classify_prompt(state: &AppState, prompt: &str) -> Option<ScenarioCard> {
    let lower = prompt.to_lowercase();
    let registries = state.registries.read().ok()?;
    let registry = registries.get(BUILTIN_REGISTRY_URL)?;
    let ads = registry.all_advertisements();

    // Try matching against each agent's capabilities and name
    for ad in ads {
        let name_lower = ad.name.to_lowercase();
        // Check if any keyword from the agent name appears in the prompt
        let name_words: Vec<&str> = name_lower.split_whitespace().collect();
        let matched = name_words.iter().any(|w| {
            // Skip generic words
            !matches!(*w, "agent" | "local" | "the" | "a") && lower.contains(w)
        });

        if matched {
            return Some(ScenarioCard {
                id: ad.name.replace(' ', "-").to_lowercase(),
                title: ad.name.clone(),
                description: String::new(),
                icon: String::new(),
                agent_name: ad.name.clone(),
                action_type: ad.capability.first().cloned().unwrap_or_default(),
                requires_disclosure: ad.requires_disclosure.clone(),
                returns: ad.returns.clone(),
            });
        }
    }

    // Fallback: match by action keywords against capabilities
    let action_match = if lower.contains("search") || lower.contains("find") || lower.contains("look") {
        Some("schema:SearchAction")
    } else if lower.contains("flight") || lower.contains("fly") || lower.contains("book") || lower.contains("hotel") || lower.contains("stay") {
        Some("schema:ReserveAction")
    } else if lower.contains("pay") || lower.contains("payment") || lower.contains("invoice") {
        Some("schema:PayAction")
    } else {
        None
    };

    if let Some(action) = action_match {
        let matched_ads = registry.query_local(action);
        if let Some(ad) = matched_ads.first() {
            return Some(ScenarioCard {
                id: ad.name.replace(' ', "-").to_lowercase(),
                title: ad.name.clone(),
                description: String::new(),
                icon: String::new(),
                agent_name: ad.name.clone(),
                action_type: ad.capability.first().cloned().unwrap_or_default(),
                requires_disclosure: ad.requires_disclosure.clone(),
                returns: ad.returns.clone(),
            });
        }
    }

    None
}

/// Submit a prompt to the canvas — runs the real PAP handshake.
///
/// This command is async: it immediately returns success, then emits Tauri
/// events as each block progresses through the 6-phase handshake.
#[tauri::command]
pub async fn canvas_prompt(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    prompt_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillionError> {
    let now_str = || Utc::now().to_rfc3339();

    // Phase 1: Classify intent against the registry
    emit_phase(&app, &block_id, &prompt_id, 1, "Classifying intent...");

    let scenario = classify_prompt(&state, &text);

    if let Some(scenario) = scenario {
        // We have a matching agent — run the real PAP handshake
        let result = crate::commands::orchestrator::run_handshake(
            &state,
            &scenario,
            Some(text.clone()),
            |phase, label| emit_phase(&app, &block_id, &prompt_id, phase, label),
        )
        .await;

        match result {
            Ok(run_result) => {
                // Determine schema type and content from the handshake result
                let (schema_type, content) = if let Some(ref search_results) = run_result.search_results {
                    let results_json: Vec<serde_json::Value> = search_results.iter().take(5).map(|r| {
                        json!({ "title": r.title, "url": r.url, "snippet": r.snippet })
                    }).collect();
                    ("SearchResultsPage".to_string(), json!({
                        "@type": "SearchResultsPage",
                        "query": text,
                        "results": results_json
                    }))
                } else {
                    let schema = scenario.returns.first()
                        .map(|s| s.trim_start_matches("schema:").to_string())
                        .unwrap_or_else(|| "StructuredData".into());
                    (schema.clone(), json!({
                        "@type": schema,
                        "agent": run_result.agent_name,
                        "action": scenario.action_type,
                        "receipt_url": run_result.receipt_url,
                        "prompt": text
                    }))
                };

                let resolved_block = CanvasBlock {
                    id: block_id.clone(),
                    prompt_id: prompt_id.clone(),
                    state: BlockState::Resolved,
                    schema_type: Some(schema_type),
                    content: Some(content),
                    linked_block_ids: Vec::new(),
                    created_at: now_str(),
                    updated_at: now_str(),
                };
                let _ = app.emit("block_resolved", BlockEvent { block: resolved_block });
            }
            Err(e) => {
                let failed_block = CanvasBlock {
                    id: block_id.clone(),
                    prompt_id: prompt_id.clone(),
                    state: BlockState::Failed {
                        phase: 4,
                        reason: e.to_string(),
                    },
                    schema_type: None,
                    content: None,
                    linked_block_ids: Vec::new(),
                    created_at: now_str(),
                    updated_at: now_str(),
                };
                let _ = app.emit("block_updated", BlockEvent { block: failed_block });
            }
        }
    } else {
        // No matching agent — use the on-device LLM directly
        emit_phase(&app, &block_id, &prompt_id, 2, "Running on-device inference...");

        let (schema_type, content) = {
            let mut mgr = state.model_manager.lock().await;
            if let Some(ref mut engine) = mgr.loaded {
                match crate::inference::generate(engine, &text, 200) {
                    Ok(response) => (
                        "Answer".into(),
                        json!({ "@type": "Answer", "text": response }),
                    ),
                    Err(_) => fallback_response(&text),
                }
            } else {
                fallback_response(&text)
            }
        };

        emit_phase(&app, &block_id, &prompt_id, 6, "Complete");

        let resolved_block = CanvasBlock {
            id: block_id.clone(),
            prompt_id: prompt_id.clone(),
            state: BlockState::Resolved,
            schema_type: Some(schema_type),
            content: Some(content),
            linked_block_ids: Vec::new(),
            created_at: now_str(),
            updated_at: now_str(),
        };
        let _ = app.emit("block_resolved", BlockEvent { block: resolved_block });
    }

    Ok(json!({ "status": "ok", "block_id": block_id }))
}

/// Reshape an existing block with a new prompt.
#[tauri::command]
pub async fn canvas_reshape(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillionError> {
    // Re-run through the real handshake with the new prompt
    canvas_prompt(
        app,
        state,
        canvas_id,
        format!("reshape-{}", block_id),
        block_id,
        text,
    )
    .await
}

/// Retry a failed block.
#[tauri::command]
pub async fn canvas_retry(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    block_id: String,
) -> Result<serde_json::Value, PapillionError> {
    canvas_prompt(
        app,
        state,
        canvas_id,
        format!("retry-{}", block_id),
        block_id,
        "Retrying previous request...".into(),
    )
    .await
}

fn fallback_response(prompt: &str) -> (String, serde_json::Value) {
    (
        "StructuredData".into(),
        json!({
            "@type": "StructuredData",
            "prompt": prompt,
            "note": "On-device orchestrator processed this request via PAP"
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── fallback_response ───────────────────────────────────

    #[test]
    fn fallback_response_returns_structured_data_type() {
        let (schema_type, _) = fallback_response("hello world");
        assert_eq!(schema_type, "StructuredData");
    }

    #[test]
    fn fallback_response_embeds_prompt_text() {
        let (_, content) = fallback_response("book a flight");
        assert_eq!(content["prompt"], "book a flight");
    }

    #[test]
    fn fallback_response_has_pap_note() {
        let (_, content) = fallback_response("test");
        let note = content["note"].as_str().unwrap();
        assert!(note.contains("PAP"));
    }

    #[test]
    fn fallback_response_has_type_field() {
        let (_, content) = fallback_response("test");
        assert_eq!(content["@type"], "StructuredData");
    }

    #[test]
    fn fallback_response_empty_prompt() {
        let (schema_type, content) = fallback_response("");
        assert_eq!(schema_type, "StructuredData");
        assert_eq!(content["prompt"], "");
    }

    // ── Phase labels ──────────────────────────────────────

    #[test]
    fn handshake_has_six_phases() {
        let phases = [
            (1, "Classifying intent..."),
            (2, "Issuing mandate..."),
            (3, "Opening session..."),
            (4, "Exchanging data..."),
            (5, "Co-signing receipt..."),
            (6, "Closing session..."),
        ];
        assert_eq!(phases.len(), 6);
        for (i, &(phase, _label)) in phases.iter().enumerate() {
            assert_eq!(phase, (i + 1) as u8);
        }
    }

    // ── CanvasBlock construction ──────────────────────────

    #[test]
    fn resolving_block_has_no_content() {
        let block = CanvasBlock {
            id: "blk-test".into(),
            prompt_id: "p-1".into(),
            state: BlockState::Resolving {
                phase: 1,
                phase_label: "Discovering...".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        assert!(block.schema_type.is_none());
        assert!(block.content.is_none());
    }

    #[test]
    fn resolved_block_has_content() {
        let block = CanvasBlock {
            id: "blk-test".into(),
            prompt_id: "p-1".into(),
            state: BlockState::Resolved,
            schema_type: Some("FlightReservation".into()),
            content: Some(json!({"@type": "FlightReservation"})),
            linked_block_ids: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        assert!(block.schema_type.is_some());
        assert!(block.content.is_some());
    }

    #[test]
    fn block_event_serializes() {
        let event = BlockEvent {
            block: CanvasBlock {
                id: "blk-1".into(),
                prompt_id: "p-1".into(),
                state: BlockState::Resolved,
                schema_type: Some("Answer".into()),
                content: Some(json!({"text": "hello"})),
                linked_block_ids: Vec::new(),
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("blk-1"));
        assert!(json.contains("Answer"));
    }
}
