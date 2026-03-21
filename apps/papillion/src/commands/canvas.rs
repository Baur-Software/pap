use chrono::Utc;
use serde_json::json;
use tauri::{AppHandle, Emitter, State};

use pap_did::PrincipalKeypair;

use crate::error::PapillionError;
use crate::handshake;
use crate::state::{AppState, LOCAL_REGISTRY_URL};
use papillion_shared::{BlockEvent, BlockState, CanvasBlock};

/// Detect intent from a user prompt.
/// Returns (action_type, preferred_agent_name, cleaned_query).
fn detect_intent(prompt: &str) -> (&'static str, &'static str, String) {
    let lower = prompt.to_lowercase();

    if lower.contains("wikipedia") || lower.contains("wiki")
        || lower.contains("article about") || lower.contains("tell me about")
    {
        let q = prompt.replace("wikipedia", "").replace("wiki", "")
            .replace("article about", "").replace("tell me about", "")
            .trim().to_string();
        ("schema:SearchAction", "Wikipedia Knowledge", if q.is_empty() { prompt.into() } else { q })
    } else if lower.contains("search") || lower.contains("find")
        || lower.contains("look up") || lower.starts_with("what is")
        || lower.starts_with("who is")
    {
        let q = prompt.replace("search", "").replace("find", "")
            .replace("look up", "").trim().to_string();
        ("schema:SearchAction", "DuckDuckGo Search", if q.is_empty() { prompt.into() } else { q })
    } else {
        ("schema:AskAction", "On-Device AI", prompt.to_string())
    }
}

/// Discover agent from registry, resolve handler, run handshake.
async fn process_prompt(
    app: &AppHandle,
    state: &State<'_, AppState>,
    prompt_id: &str,
    block_id: &str,
    text: &str,
) -> Result<(String, serde_json::Value), PapillionError> {
    let (action_type, preferred, query) = detect_intent(text);

    // Discover agent from federated registry
    let (agent_name, agent_did, requires_disclosure, returns) = {
        let registries = state.registries.read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let registry = registries.get(LOCAL_REGISTRY_URL)
            .ok_or_else(|| PapillionError::from("No registry available"))?;

        let candidates = registry.query_local_satisfiable(action_type, &[]);
        if candidates.is_empty() {
            return Err(PapillionError::from(format!("No agent for {}", action_type)));
        }

        let agent = candidates.iter()
            .find(|a| a.name == preferred)
            .unwrap_or(&candidates[0]);

        (agent.name.clone(), agent.provider.did.clone(),
         agent.requires_disclosure.clone(), agent.returns.clone())
    };

    // Resolve local handler (zero-trust: same interface as remote)
    let handler = state.local_agents.get(&agent_name)
        .ok_or_else(|| PapillionError::from(format!("No handler for {}", agent_name)))?
        .clone();

    // Get principal keypair
    let principal_kp = {
        let seed = state.principal_seed.read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let seed = seed.as_ref()
            .ok_or_else(|| PapillionError::from("No identity configured"))?;
        PrincipalKeypair::from_bytes(seed)
            .map_err(|e| PapillionError::from(e.to_string()))?
    };

    // Phase progress callbacks emit Tauri events
    let bid = block_id.to_string();
    let pid = prompt_id.to_string();
    let app_phase = app.clone();
    let on_phase: handshake::PhaseCallback = Box::new(move |phase, label| {
        let now = Utc::now().to_rfc3339();
        let block = CanvasBlock {
            id: bid.clone(), prompt_id: pid.clone(),
            state: BlockState::Resolving { phase, phase_label: label.into() },
            schema_type: None, content: None, linked_block_ids: Vec::new(),
            created_at: now.clone(), updated_at: now,
        };
        let _ = app_phase.emit("block_updated", BlockEvent { block });
    });

    let bid2 = block_id.to_string();
    let pid2 = prompt_id.to_string();
    let app_fail = app.clone();
    let on_fail: handshake::FailCallback = Box::new(move |phase, reason| {
        let now = Utc::now().to_rfc3339();
        let block = CanvasBlock {
            id: bid2.clone(), prompt_id: pid2.clone(),
            state: BlockState::Failed { phase, reason: reason.into() },
            schema_type: None, content: None, linked_block_ids: Vec::new(),
            created_at: now.clone(), updated_at: now,
        };
        let _ = app_fail.emit("block_resolved", BlockEvent { block });
    });

    let result = handshake::execute(
        handler, &agent_name, &agent_did, action_type, &query,
        &principal_kp, &requires_disclosure, &returns,
        on_phase, on_fail,
    ).await?;

    Ok((result.schema_type, result.content))
}

#[tauri::command]
pub async fn canvas_prompt(
    app: AppHandle, state: State<'_, AppState>,
    _canvas_id: String, prompt_id: String, block_id: String, text: String,
) -> Result<serde_json::Value, PapillionError> {
    let (schema_type, content) = process_prompt(&app, &state, &prompt_id, &block_id, &text).await?;

    let now = Utc::now().to_rfc3339();
    let _ = app.emit("block_resolved", BlockEvent {
        block: CanvasBlock {
            id: block_id.clone(), prompt_id, state: BlockState::Resolved,
            schema_type: Some(schema_type), content: Some(content),
            linked_block_ids: Vec::new(), created_at: now.clone(), updated_at: now,
        },
    });
    Ok(json!({ "status": "ok", "block_id": block_id }))
}

#[tauri::command]
pub async fn canvas_reshape(
    app: AppHandle, state: State<'_, AppState>,
    _canvas_id: String, block_id: String, text: String,
) -> Result<serde_json::Value, PapillionError> {
    let (schema_type, content) = process_prompt(&app, &state, "", &block_id, &text).await?;

    let now = Utc::now().to_rfc3339();
    let _ = app.emit("block_resolved", BlockEvent {
        block: CanvasBlock {
            id: block_id.clone(), prompt_id: String::new(), state: BlockState::Resolved,
            schema_type: Some(schema_type), content: Some(content),
            linked_block_ids: Vec::new(), created_at: now.clone(), updated_at: now,
        },
    });
    Ok(json!({ "status": "ok", "block_id": block_id }))
}

#[tauri::command]
pub async fn canvas_retry(
    app: AppHandle, state: State<'_, AppState>,
    canvas_id: String, block_id: String,
) -> Result<serde_json::Value, PapillionError> {
    canvas_prompt(app, state, canvas_id, format!("retry-{}", block_id), block_id,
        "Retrying previous request...".into()).await
}
