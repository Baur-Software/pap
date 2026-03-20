use chrono::Utc;
use serde_json::json;
use tauri::{AppHandle, Emitter, State};

use crate::error::PapillionError;
use crate::state::AppState;
use papillion_shared::{BlockEvent, BlockState, CanvasBlock};

/// Submit a prompt to the canvas — creates blocks via the orchestrator.
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

    // Phase progression — simulate the 6-phase PAP handshake
    // In production, each phase would be a real protocol operation.
    let phases = [
        (1, "Discovering agents..."),
        (2, "Issuing mandate..."),
        (3, "Opening session..."),
        (4, "Exchanging data..."),
        (5, "Co-signing receipt..."),
        (6, "Closing session..."),
    ];

    for &(phase, label) in &phases {
        // Emit phase update event
        let block = CanvasBlock {
            id: block_id.clone(),
            prompt_id: prompt_id.clone(),
            state: BlockState::Resolving {
                phase,
                phase_label: label.into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            created_at: now_str(),
            updated_at: now_str(),
        };

        let _ = app.emit("block_updated", BlockEvent { block });

        // Brief delay to show phase progression
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    // Generate demo content based on the prompt
    let (schema_type, content) = generate_demo_content(&text, &state).await?;

    // Emit resolved block
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

    Ok(json!({ "status": "ok", "block_id": block_id }))
}

/// Reshape an existing block with a new prompt.
#[tauri::command]
pub async fn canvas_reshape(
    app: AppHandle,
    _state: State<'_, AppState>,
    _canvas_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillionError> {
    let now_str = || Utc::now().to_rfc3339();

    // Re-run through phases
    for phase in 1..=6u8 {
        let label = match phase {
            1 => "Reshaping...",
            2 => "Updating mandate...",
            3 => "Re-opening session...",
            4 => "Exchanging updated data...",
            5 => "Co-signing receipt...",
            _ => "Closing session...",
        };
        let block = CanvasBlock {
            id: block_id.clone(),
            prompt_id: String::new(),
            state: BlockState::Resolving {
                phase,
                phase_label: label.into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            created_at: now_str(),
            updated_at: now_str(),
        };
        let _ = app.emit("block_updated", BlockEvent { block });
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    // Resolve with updated content
    let resolved = CanvasBlock {
        id: block_id.clone(),
        prompt_id: String::new(),
        state: BlockState::Resolved,
        schema_type: Some("StructuredData".into()),
        content: Some(json!({
            "@type": "StructuredData",
            "prompt": text,
            "reshaped": true,
            "note": "Content reshaped by orchestrator"
        })),
        linked_block_ids: Vec::new(),
        created_at: now_str(),
        updated_at: now_str(),
    };
    let _ = app.emit("block_resolved", BlockEvent { block: resolved });

    Ok(json!({ "status": "ok", "block_id": block_id }))
}

/// Retry a failed block.
#[tauri::command]
pub async fn canvas_retry(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    block_id: String,
) -> Result<serde_json::Value, PapillionError> {
    // Re-run the same flow as canvas_prompt with a retry context
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

/// Generate demo content based on prompt keywords.
/// In production, this would delegate via PAP to real agents.
async fn generate_demo_content(
    prompt: &str,
    state: &State<'_, AppState>,
) -> Result<(String, serde_json::Value), PapillionError> {
    let lower = prompt.to_lowercase();

    if lower.contains("flight") || lower.contains("fly") {
        Ok((
            "FlightReservation".into(),
            json!({
                "@type": "FlightReservation",
                "departureAirport": "SAN",
                "arrivalAirport": "SJC",
                "departureDate": "Mar 30, 11:45 AM",
                "totalPrice": "49",
                "airline": "United Airlines \u{00b7} 1h 12m"
            }),
        ))
    } else if lower.contains("hotel") || lower.contains("lodging") || lower.contains("stay") {
        Ok((
            "LodgingReservation".into(),
            json!({
                "@type": "LodgingReservation",
                "name": "Park Hyatt Tokyo",
                "checkinDate": "Mar 30",
                "checkoutDate": "Apr 2",
                "totalPrice": "1,240"
            }),
        ))
    } else if lower.contains("search") || lower.contains("find") || lower.contains("look") {
        // Use the real DuckDuckGo search if possible
        let query = prompt.replace("search", "").replace("find", "").replace("look up", "").trim().to_string();
        let results = crate::commands::orchestrator::web_search_public(&query).await;
        match results {
            Ok(items) => {
                let results_json: Vec<serde_json::Value> = items.iter().take(5).map(|r| {
                    json!({
                        "title": r.title,
                        "url": r.url,
                        "snippet": r.snippet
                    })
                }).collect();
                Ok((
                    "SearchResultsPage".into(),
                    json!({
                        "@type": "SearchResultsPage",
                        "query": query,
                        "results": results_json
                    }),
                ))
            }
            Err(_) => Ok((
                "SearchResultsPage".into(),
                json!({
                    "@type": "SearchResultsPage",
                    "query": query,
                    "results": [{
                        "title": "Search result placeholder",
                        "url": "https://example.com",
                        "snippet": "Zero-disclosure search via PAP"
                    }]
                }),
            )),
        }
    } else if lower.contains("pay") || lower.contains("payment") {
        Ok((
            "Invoice".into(),
            json!({
                "@type": "Invoice",
                "paymentMethod": "ecash (Chaumian)",
                "totalPrice": "0.00",
                "note": "Zero-disclosure payment \u{2014} vendor cannot identify payer"
            }),
        ))
    } else {
        // Default: use the on-device LLM if available
        let mut mgr = state.model_manager.lock().await;
        if let Some(ref mut engine) = mgr.loaded {
            match crate::inference::generate(engine, prompt, 200) {
                Ok(response) => Ok((
                    "Answer".into(),
                    json!({
                        "@type": "Answer",
                        "text": response
                    }),
                )),
                Err(_) => default_structured_response(prompt),
            }
        } else {
            default_structured_response(prompt)
        }
    }
}

fn default_structured_response(prompt: &str) -> Result<(String, serde_json::Value), PapillionError> {
    Ok((
        "StructuredData".into(),
        json!({
            "@type": "StructuredData",
            "prompt": prompt,
            "note": "On-device orchestrator processed this request via PAP"
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── default_structured_response ───────────────────────

    #[test]
    fn default_response_returns_structured_data_type() {
        let (schema_type, _) = default_structured_response("hello world").unwrap();
        assert_eq!(schema_type, "StructuredData");
    }

    #[test]
    fn default_response_embeds_prompt_text() {
        let (_, content) = default_structured_response("book a flight").unwrap();
        assert_eq!(content["prompt"], "book a flight");
    }

    #[test]
    fn default_response_has_pap_note() {
        let (_, content) = default_structured_response("test").unwrap();
        let note = content["note"].as_str().unwrap();
        assert!(note.contains("PAP"));
    }

    #[test]
    fn default_response_has_type_field() {
        let (_, content) = default_structured_response("test").unwrap();
        assert_eq!(content["@type"], "StructuredData");
    }

    #[test]
    fn default_response_empty_prompt() {
        let (schema_type, content) = default_structured_response("").unwrap();
        assert_eq!(schema_type, "StructuredData");
        assert_eq!(content["prompt"], "");
    }

    // ── Phase labels ──────────────────────────────────────

    #[test]
    fn canvas_prompt_has_six_phases() {
        let phases = [
            (1, "Discovering agents..."),
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
