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

    // Route to real agents based on the prompt
    let (schema_type, content) = route_to_agent(&text, &state).await?;

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
    state: State<'_, AppState>,
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

    // Route to real agents for the reshaped content
    let (schema_type, content) = route_to_agent(&text, &state).await?;

    let resolved = CanvasBlock {
        id: block_id.clone(),
        prompt_id: String::new(),
        state: BlockState::Resolved,
        schema_type: Some(schema_type),
        content: Some(content),
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

/// Route a prompt to real agents via PAP.
///
/// Uses simple intent detection to select the appropriate agent, then
/// executes the actual service call. No hardcoded responses.
async fn route_to_agent(
    prompt: &str,
    state: &State<'_, AppState>,
) -> Result<(String, serde_json::Value), PapillionError> {
    let lower = prompt.to_lowercase();

    // Intent detection: search, knowledge lookup, or general AI query
    let is_wiki = lower.contains("wikipedia")
        || lower.contains("wiki")
        || lower.contains("article about")
        || lower.contains("tell me about");

    let is_search = lower.contains("search")
        || lower.contains("find")
        || lower.contains("look up")
        || lower.starts_with("what is")
        || lower.starts_with("who is");

    if is_wiki {
        let query = prompt
            .replace("wikipedia", "")
            .replace("wiki", "")
            .replace("article about", "")
            .replace("tell me about", "")
            .trim()
            .to_string();
        let query = if query.is_empty() { prompt.to_string() } else { query };
        let items = crate::commands::orchestrator::wikipedia_search_public(&query).await?;
        let results_json: Vec<serde_json::Value> = items
            .iter()
            .take(5)
            .map(|r| {
                json!({
                    "title": r.title,
                    "url": r.url,
                    "snippet": r.snippet
                })
            })
            .collect();
        Ok((
            "SearchResultsPage".into(),
            json!({
                "@type": "SearchResultsPage",
                "agent": "Wikipedia Knowledge",
                "query": query,
                "results": results_json
            }),
        ))
    } else if is_search {
        let query = prompt
            .replace("search", "")
            .replace("find", "")
            .replace("look up", "")
            .trim()
            .to_string();
        let query = if query.is_empty() { prompt.to_string() } else { query };
        let items = crate::commands::orchestrator::web_search_public(&query).await?;
        let results_json: Vec<serde_json::Value> = items
            .iter()
            .take(5)
            .map(|r| {
                json!({
                    "title": r.title,
                    "url": r.url,
                    "snippet": r.snippet
                })
            })
            .collect();
        Ok((
            "SearchResultsPage".into(),
            json!({
                "@type": "SearchResultsPage",
                "agent": "DuckDuckGo Search",
                "query": query,
                "results": results_json
            }),
        ))
    } else {
        // Default: route to on-device Mistral
        let mut mgr = state.model_manager.lock().await;
        if mgr.loaded.is_some() {
            let mistral_prompt = format!("[INST] {} [/INST]", prompt);
            match mgr.generate(&mistral_prompt, 300) {
                Ok(response) => Ok((
                    "Answer".into(),
                    json!({
                        "@type": "Answer",
                        "agent": "On-Device AI",
                        "text": response
                    }),
                )),
                Err(e) => Err(PapillionError::from(format!("Mistral inference: {e}"))),
            }
        } else {
            // No model loaded — try DuckDuckGo as fallback
            match crate::commands::orchestrator::web_search_public(prompt).await {
                Ok(items) if !items.is_empty() => {
                    let results_json: Vec<serde_json::Value> = items
                        .iter()
                        .take(5)
                        .map(|r| {
                            json!({
                                "title": r.title,
                                "url": r.url,
                                "snippet": r.snippet
                            })
                        })
                        .collect();
                    Ok((
                        "SearchResultsPage".into(),
                        json!({
                            "@type": "SearchResultsPage",
                            "agent": "DuckDuckGo Search",
                            "query": prompt,
                            "results": results_json
                        }),
                    ))
                }
                _ => Err(PapillionError::from(
                    "No LLM loaded and search returned no results. Configure a provider in Settings.",
                )),
            }
        }
    }
}
