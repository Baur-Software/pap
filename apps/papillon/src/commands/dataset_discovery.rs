//! Multi-agent fan-out coordinator for dataset discovery.
//!
//! Routes `schema:DatasetAction` intents through the full 6-phase PAP handshake
//! in parallel across all registered zero-disclosure dataset agents.
//! Uses the long-horizon memex for prior-art caching and preference learning.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use pap_did::PrincipalKeypair;
use pap_transport::AgentHandler;
use serde_json::json;
use tauri::{AppHandle, Emitter, State};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::db::{prelude::DatabaseOps, Episode};
use crate::error::PapillonError;
use crate::handshake;
use crate::state::AppState;
use papillon_shared::{
    BlockEvent, BlockState, CanvasBlock, DatasetDiscoveryState, DatasetResult, PreferenceEngine,
};

use super::orchestrator::hash_agent_did;

// ── Local agent reference ─────────────────────────────────────────────────────

/// A resolved dataset agent ready for handshake execution.
#[derive(Clone)]
struct DatasetAgent {
    pub name: String,
    pub did: String,
    pub handler: Arc<dyn AgentHandler>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
}

// ── Agent resolution ──────────────────────────────────────────────────────────

/// Resolve all zero-disclosure dataset agents from the local registry.
///
/// Uses `query_local("schema:DatasetAction")` — same pattern as canvas.rs
/// resolve_agent but returns ALL matching agents instead of the top-scored one.
fn resolve_all_dataset_agents(state: &AppState) -> Vec<DatasetAgent> {
    let local = match state.local_registry.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    local
        .query_local("schema:DatasetAction")
        .into_iter()
        .filter_map(|ad| {
            let handler = state.local_agents.get(&ad.name)?.clone();
            Some(DatasetAgent {
                name: ad.name.clone(),
                did: ad.provider.did.clone(),
                handler,
                requires_disclosure: ad.requires_disclosure.clone(),
                returns: ad.returns.clone(),
            })
        })
        .collect()
}

// ── Memex helpers ─────────────────────────────────────────────────────────────

/// Check the episode store for a recent `schema:DatasetAction` result matching this query.
/// Returns `Some((results, cached_at_iso))` if a fresh cache hit exists within `ttl_days`.
fn check_memex_prior_results(
    db: &dyn DatabaseOps,
    query: &str,
    ttl_days: i64,
) -> Option<(Vec<DatasetResult>, String)> {
    let episodes = db.search_episodes(query, 5).unwrap_or_default();
    let cutoff = Utc::now() - chrono::Duration::days(ttl_days);
    let cutoff_str = cutoff.to_rfc3339();

    for ep in &episodes {
        if ep.action_type != "schema:DatasetAction" {
            continue;
        }
        if ep.outcome != "success" {
            continue;
        }
        // TTL check: episode recorded_at must be within the window
        if ep.recorded_at < cutoff_str {
            continue;
        }
        // Extract DatasetResult list from the stored JSON-LD ItemList
        if let Some(result_json) = &ep.result_json {
            if let Ok(results) = extract_dataset_results_from_jsonld(result_json) {
                if !results.is_empty() {
                    return Some((results, ep.recorded_at.clone()));
                }
            }
        }
    }
    None
}

/// Extract `DatasetResult` items from a stored schema:ItemList JSON blob.
fn extract_dataset_results_from_jsonld(json_str: &str) -> Result<Vec<DatasetResult>, String> {
    let v: serde_json::Value = serde_json::from_str(json_str).map_err(|e| e.to_string())?;

    // The stored blob is the `content` field from `block_resolved`.
    // Look for `result.itemListElement` (schema:ItemList) or `result` array.
    let items = if let Some(items) = v
        .get("result")
        .and_then(|r| r.get("itemListElement"))
        .and_then(|e| e.as_array())
    {
        items.to_vec()
    } else if let Some(arr) = v.get("result").and_then(|r| r.as_array()) {
        arr.to_vec()
    } else if let Some(arr) = v.get("itemListElement").and_then(|e| e.as_array()) {
        arr.to_vec()
    } else {
        return Ok(vec![]);
    };

    let results: Vec<DatasetResult> = items
        .iter()
        .filter_map(|item| {
            let item_obj = item.get("item").unwrap_or(item);
            let name = item_obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if name.is_empty() {
                return None;
            }
            Some(DatasetResult {
                schema_type: "Dataset".to_string(),
                name: name.to_string(),
                description: item_obj
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                url: item_obj
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                encoding_format: item_obj
                    .get("encodingFormat")
                    .and_then(|v| v.as_str())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default(),
                license: item_obj
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                creator: item_obj
                    .get("creator")
                    .and_then(|v| v.get("name").and_then(|n| n.as_str()))
                    .or_else(|| item_obj.get("author").and_then(|v| v.as_str()))
                    .map(|s| s.to_string()),
                date_modified: item_obj
                    .get("dateModified")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                distribution: item_obj
                    .get("distribution")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|d| {
                                d.get("contentUrl")
                                    .and_then(|u| u.as_str())
                                    .map(|s| s.to_string())
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                source_agent: item_obj
                    .get("sourceAgent")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                source_agent_did: item_obj
                    .get("sourceAgentDid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                relevance_score: item_obj
                    .get("relevanceScore")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5),
                croissant_metadata: item_obj.get("croissantMetadata").cloned(),
                from_memex: true,
            })
        })
        .collect();

    Ok(results)
}

// ── Preference helpers ────────────────────────────────────────────────────────

fn preference_scores_for_agents(
    db: &dyn DatabaseOps,
    agents: &[DatasetAgent],
) -> HashMap<String, f64> {
    let engine = PreferenceEngine::new(db);
    agents
        .iter()
        .map(|a| {
            let hash = hash_agent_did(&a.did);
            let score = engine.preference_score("schema:DatasetAction", "Dataset", &hash);
            (a.name.clone(), score)
        })
        .collect()
}

fn record_preference_signals(db: &dyn DatabaseOps, agent: &DatasetAgent, success: bool) {
    let hash = hash_agent_did(&agent.did);
    let engine = PreferenceEngine::new(db);
    engine.record_agent_selected("schema:DatasetAction", "Dataset", &hash, &agent.name);
    engine.record_outcome("schema:DatasetAction", "Dataset", &hash, success);
}

// ── Episode recording ─────────────────────────────────────────────────────────

fn record_agent_episode(
    db: &dyn DatabaseOps,
    agent: &DatasetAgent,
    query: &str,
    results: &[DatasetResult],
    success: bool,
    elapsed_ms: i64,
) {
    let result_json = if !results.is_empty() {
        let items: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                json!({
                    "@type": "schema:Dataset",
                    "name": r.name,
                    "description": r.description,
                    "url": r.url,
                    "sourceAgent": r.source_agent,
                    "sourceAgentDid": r.source_agent_did,
                    "relevanceScore": r.relevance_score,
                })
            })
            .collect();
        Some(serde_json::to_string(&json!({ "items": items })).unwrap_or_default())
    } else {
        None
    };

    let ep = Episode {
        id: Uuid::new_v4().to_string(),
        receipt_session_id: Uuid::new_v4().to_string(),
        scenario_id: String::new(),
        action_type: "schema:DatasetAction".to_string(),
        agent_did_hash: hash_agent_did(&agent.did),
        agent_name: agent.name.clone(),
        outcome: if success {
            "success".to_string()
        } else {
            "failure".to_string()
        },
        outcome_detail: None,
        scope_exercised: r#"["schema:DatasetAction"]"#.to_string(),
        disclosure_refs: "[]".to_string(),
        duration_ms: elapsed_ms,
        decay_state: "Active".to_string(),
        intent_summary: Some(format!("Dataset search: {query}")),
        result_json,
        query: Some(query.to_string()),
        recorded_at: Utc::now().to_rfc3339(),
    };
    let _ = db.insert_episode(&ep);
}

fn record_aggregate_episode(
    db: &dyn DatabaseOps,
    query: &str,
    all_results: &[DatasetResult],
    content: &serde_json::Value,
    elapsed_ms: i64,
) {
    let ep = Episode {
        id: Uuid::new_v4().to_string(),
        receipt_session_id: Uuid::new_v4().to_string(),
        scenario_id: String::new(),
        action_type: "schema:DatasetAction".to_string(),
        agent_did_hash: "aggregate".to_string(),
        agent_name: "Dataset Discovery (aggregate)".to_string(),
        outcome: if all_results.is_empty() {
            "failure"
        } else {
            "success"
        }
        .to_string(),
        outcome_detail: None,
        scope_exercised: r#"["schema:DatasetAction"]"#.to_string(),
        disclosure_refs: "[]".to_string(),
        duration_ms: elapsed_ms,
        decay_state: "Active".to_string(),
        intent_summary: Some(format!("Dataset discovery: {query}")),
        result_json: Some(content.to_string()),
        query: Some(query.to_string()),
        recorded_at: Utc::now().to_rfc3339(),
    };
    let _ = db.insert_episode(&ep);
}

// ── Handshake execution ───────────────────────────────────────────────────────

/// Run the full 6-phase PAP handshake for one dataset agent.
///
/// Zero-disclosure agents skip the approval gate and proceed directly.
/// Returns a list of DatasetResult items extracted from the agent's response.
async fn run_dataset_handshake(
    app: AppHandle,
    agent: DatasetAgent,
    query: String,
    block_id: String,
    prompt_id: String,
    seed: [u8; 32],
    agent_index: usize,
    total_agents: usize,
) -> Result<Vec<DatasetResult>, String> {
    let agent_name = agent.name.clone();
    let agent_did = agent.did.clone();

    // Reconstruct keypair from seed — PrincipalKeypair doesn't implement Clone
    let principal_kp = PrincipalKeypair::from_bytes(&seed)
        .map_err(|e| format!("Failed to reconstruct keypair: {e}"))?;

    let app_phase = app.clone();
    let block_id_phase = block_id.clone();
    let prompt_id_phase = prompt_id.clone();
    let agent_name_phase = agent_name.clone();

    let on_phase: handshake::PhaseCallback = Box::new(move |phase, label| {
        let now = Utc::now().to_rfc3339();
        let display_label = format!(
            "[{}/{}] {} — {}",
            agent_index + 1,
            total_agents,
            agent_name_phase,
            label
        );
        let _ = app_phase.emit(
            "block_updated",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id_phase.clone(),
                    prompt_id: prompt_id_phase.clone(),
                    prompt_text: None,
                    state: BlockState::Resolving {
                        phase,
                        phase_label: display_label,
                    },
                    schema_type: None,
                    content: None,
                    linked_block_ids: Vec::new(),
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
    });

    let on_fail: handshake::FailCallback = Box::new(|_phase, _reason| {
        // Failure logged through episode recording — no block update needed
        // since other agents may still succeed
    });

    let result = handshake::execute(handshake::HandshakeParams {
        handler: agent.handler,
        agent_name: &agent_name,
        agent_did: &agent_did,
        action_type: "schema:DatasetAction",
        query: &query,
        principal_kp: &principal_kp,
        requires_disclosure: &agent.requires_disclosure,
        returns: &agent.returns,
        on_phase,
        on_fail,
    })
    .await
    .map_err(|e| e.to_string())?;

    // Extract DatasetResult items from the handshake result JSON-LD
    let results = extract_results_from_handshake(&result.content, &agent_name, &agent_did);
    Ok(results)
}

/// Extract DatasetResult items from a handshake result `content` blob.
fn extract_results_from_handshake(
    content: &serde_json::Value,
    agent_name: &str,
    agent_did: &str,
) -> Vec<DatasetResult> {
    // The DynamicAgentHandler places agent data in content["result"]
    let result = match content.get("result") {
        Some(r) => r,
        None => return vec![],
    };

    // Try array of items first, then single object
    let items: Vec<&serde_json::Value> = if let Some(arr) = result.as_array() {
        arr.iter().collect()
    } else if let Some(arr) = result.get("itemListElement").and_then(|e| e.as_array()) {
        arr.iter().collect()
    } else {
        vec![result]
    };

    items
        .iter()
        .filter_map(|item| {
            let item_obj = item.get("item").unwrap_or(item);
            let name = item_obj
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if name.is_empty() {
                return None;
            }
            Some(DatasetResult {
                schema_type: "Dataset".to_string(),
                name: name.to_string(),
                description: item_obj
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                url: item_obj
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| format!("https://huggingface.co/datasets/{s}"))
                    .or_else(|| {
                        item_obj
                            .get("@id")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                    }),
                encoding_format: item_obj
                    .get("encodingFormat")
                    .and_then(|v| v.as_str())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default(),
                license: item_obj
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                creator: item_obj
                    .get("author")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        item_obj
                            .get("creator")
                            .and_then(|c| c.get("name").and_then(|n| n.as_str()))
                    })
                    .map(|s| s.to_string()),
                date_modified: item_obj
                    .get("dateModified")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                distribution: vec![],
                source_agent: agent_name.to_string(),
                source_agent_did: agent_did.to_string(),
                relevance_score: 0.5,
                croissant_metadata: None,
                from_memex: false,
            })
        })
        .collect()
}

// ── JSON-LD content builder ───────────────────────────────────────────────────

/// Build a schema:ItemList JSON-LD blob from aggregated DatasetResults.
/// This is the `content` stored in the CanvasBlock for `DatasetSearchResults`.
fn build_dataset_jsonld_itemlist(results: &[DatasetResult]) -> serde_json::Value {
    let items: Vec<serde_json::Value> = results
        .iter()
        .enumerate()
        .map(|(i, r)| {
            json!({
                "@type": "ListItem",
                "position": i + 1,
                "item": {
                    "@type": "Dataset",
                    "name": r.name,
                    "description": r.description,
                    "url": r.url,
                    "license": r.license,
                    "creator": r.creator.as_ref().map(|c| json!({ "@type": "Person", "name": c })),
                    "dateModified": r.date_modified,
                    "encodingFormat": r.encoding_format.first(),
                    "sourceAgent": r.source_agent,
                    "sourceAgentDid": r.source_agent_did,
                    "relevanceScore": r.relevance_score,
                    "fromMemex": r.from_memex,
                    "croissantMetadata": r.croissant_metadata,
                }
            })
        })
        .collect();

    json!({
        "@context": "https://schema.org",
        "@type": "ItemList",
        "itemListElement": items,
        "numberOfItems": results.len(),
    })
}

// ── Tauri commands ────────────────────────────────────────────────────────────

/// Multi-agent fan-out dataset discovery command.
///
/// Replaces the single-agent `process_prompt_inner()` path for `schema:DatasetAction`.
/// All zero-disclosure dataset agents run in parallel via `JoinSet`, producing
/// a merged `DatasetSearchResults` block with full PAP receipt provenance.
#[tauri::command]
pub async fn canvas_discover_datasets(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    prompt_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillonError> {
    let query = text.clone();
    let start = std::time::Instant::now();

    // ── Step 0: Memex prior-art check ─────────────────────────────────────────
    let memex_hit = check_memex_prior_results(state.db.as_ref(), &query, 7);

    if let Some((cached_results, cached_at)) = &memex_hit {
        let agents_preview = resolve_all_dataset_agents(&state);
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_updated",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id.clone(),
                    prompt_id: prompt_id.clone(),
                    prompt_text: Some(text.clone()),
                    state: BlockState::Resolving {
                        phase: 1,
                        phase_label: format!(
                            "Restoring {} results from memory ({})",
                            cached_results.len(),
                            &cached_at[..10]
                        ),
                    },
                    schema_type: Some("DatasetSearchResults".into()),
                    content: Some(json!({
                        "discovery_state": serde_json::to_value(
                            DatasetDiscoveryState::RestoredFromMemex {
                                results: cached_results.clone(),
                                cached_at: cached_at.clone(),
                                agents_queried: agents_preview.len() as u8,
                            }
                        ).unwrap_or(json!(null))
                    })),
                    linked_block_ids: Vec::new(),
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
    }

    // ── Step 1: Capability fan-out ────────────────────────────────────────────
    let agents = resolve_all_dataset_agents(&state);

    if agents.is_empty() {
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id.clone(),
                    prompt_id: prompt_id.clone(),
                    prompt_text: Some(text.clone()),
                    state: BlockState::Failed {
                        phase: 1,
                        reason: "No dataset agents registered. Add a dataset agent to the catalog."
                            .into(),
                    },
                    schema_type: None,
                    content: None,
                    linked_block_ids: Vec::new(),
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
        return Ok(json!({ "status": "no_agents" }));
    }

    let preference_scores = preference_scores_for_agents(state.db.as_ref(), &agents);
    let total_agents = agents.len();

    // Emit FanningOut phase
    {
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_updated",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id.clone(),
                    prompt_id: prompt_id.clone(),
                    prompt_text: Some(text.clone()),
                    state: BlockState::Resolving {
                        phase: 2,
                        phase_label: format!(
                            "Querying {} dataset source{}…",
                            total_agents,
                            if total_agents == 1 { "" } else { "s" }
                        ),
                    },
                    schema_type: None,
                    content: None,
                    linked_block_ids: Vec::new(),
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
    }

    // ── Step 2: Get raw seed (not keypair — PrincipalKeypair doesn't impl Clone) ──
    let raw_seed: [u8; 32] = {
        let seed_guard = state
            .principal_seed
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        match seed_guard.as_ref() {
            Some(s) => **s,
            None => {
                return Err(PapillonError::from(
                    "No identity loaded — set up your principal DID first",
                ))
            }
        }
    };

    // ── Step 3: Parallel PAP handshakes ──────────────────────────────────────
    let mut join_set: JoinSet<(DatasetAgent, Result<Vec<DatasetResult>, String>, i64, f64)> =
        JoinSet::new();

    for (idx, agent) in agents.into_iter().enumerate() {
        let q = query.clone();
        let app_clone = app.clone();
        let block_id_clone = block_id.clone();
        let prompt_id_clone = prompt_id.clone();
        let pref = preference_scores.get(&agent.name).copied().unwrap_or(0.5);
        let seed = raw_seed;

        join_set.spawn(async move {
            let agent_start = std::time::Instant::now();
            let result = run_dataset_handshake(
                app_clone,
                agent.clone(),
                q,
                block_id_clone,
                prompt_id_clone,
                seed,
                idx,
                total_agents,
            )
            .await;
            let elapsed = agent_start.elapsed().as_millis() as i64;
            (agent, result, elapsed, pref)
        });
    }

    // ── Step 4: Accumulate results ────────────────────────────────────────────
    let mut all_results: Vec<DatasetResult> = Vec::new();

    while let Some(task_result) = join_set.join_next().await {
        match task_result {
            Ok((agent, Ok(mut results), elapsed, pref)) => {
                // Blend preference score into relevance ranking
                for r in &mut results {
                    r.relevance_score = r.relevance_score * (1.0 + 0.3 * pref);
                    r.source_agent_did = agent.did.clone();
                }
                all_results.extend(results.clone());

                // Record per-agent episode + preference signals
                record_agent_episode(state.db.as_ref(), &agent, &query, &results, true, elapsed);
                record_preference_signals(state.db.as_ref(), &agent, true);

                // Emit Accumulating progress
                let now = Utc::now().to_rfc3339();
                let _ = app.emit(
                    "block_updated",
                    BlockEvent {
                        block: CanvasBlock {
                            id: block_id.clone(),
                            prompt_id: prompt_id.clone(),
                            prompt_text: None,
                            state: BlockState::Resolving {
                                phase: 4,
                                phase_label: format!(
                                    "Found {} dataset{} so far…",
                                    all_results.len(),
                                    if all_results.len() == 1 { "" } else { "s" }
                                ),
                            },
                            schema_type: None,
                            content: None,
                            linked_block_ids: Vec::new(),
                            agent_did: None,
                            mandate_expires_at: None,
                            preference_guided: false,
                            created_at: now.clone(),
                            updated_at: now,
                        },
                    },
                );
            }
            Ok((agent, Err(_), elapsed, _)) => {
                record_agent_episode(state.db.as_ref(), &agent, &query, &[], false, elapsed);
                record_preference_signals(state.db.as_ref(), &agent, false);
            }
            Err(_join_err) => {
                // Task panicked — logged but not propagated
            }
        }
    }

    // Sort by relevance_score descending
    all_results.sort_by(|a, b| {
        b.relevance_score
            .partial_cmp(&a.relevance_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let total_elapsed = start.elapsed().as_millis() as i64;
    let content = build_dataset_jsonld_itemlist(&all_results);

    // ── Step 5: Emit final block_resolved ─────────────────────────────────────
    let now = Utc::now().to_rfc3339();
    let mandate_expires_at = Some((Utc::now() + chrono::Duration::days(7)).to_rfc3339());

    let block_state = if all_results.is_empty() {
        BlockState::Failed {
            phase: 6,
            reason: format!("No datasets found for '{}'. Try different keywords.", query),
        }
    } else {
        BlockState::Resolved
    };

    let _ = app.emit(
        "block_resolved",
        BlockEvent {
            block: CanvasBlock {
                id: block_id.clone(),
                prompt_id: prompt_id.clone(),
                prompt_text: Some(text.clone()),
                state: block_state,
                schema_type: Some("DatasetSearchResults".into()),
                content: Some(content.clone()),
                linked_block_ids: Vec::new(),
                agent_did: Some("dataset-discovery-aggregate".to_string()),
                mandate_expires_at,
                preference_guided: false,
                created_at: now.clone(),
                updated_at: now,
            },
        },
    );

    // ── Step 6: Aggregate episode + PersonalContext broadcast ─────────────────
    record_aggregate_episode(
        state.db.as_ref(),
        &query,
        &all_results,
        &content,
        total_elapsed,
    );
    rebuild_personal_context(&state);

    Ok(json!({ "status": "ok", "block_id": block_id, "results": all_results.len() }))
}

/// List the names of all registered dataset agents.
/// Used by the frontend DatasetState to display provider badges.
#[tauri::command]
pub fn list_dataset_agents(state: State<'_, AppState>) -> Vec<String> {
    resolve_all_dataset_agents(&state)
        .into_iter()
        .map(|a| a.name)
        .collect()
}

// ── PersonalContext broadcast ─────────────────────────────────────────────────

fn rebuild_personal_context(state: &AppState) {
    use papillon_shared::PersonalContext;

    let trait_profile = state
        .trait_beacon_profile
        .read()
        .ok()
        .map(|p| p.clone())
        .filter(|v| !v.is_null());

    let ctx = PersonalContext::from_db(state.db.as_ref(), trait_profile);
    let _ = state.context_tx.send(ctx.to_system_preamble());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_jsonld_itemlist_is_valid_json() {
        let results = vec![DatasetResult {
            name: "test_dataset".to_string(),
            description: Some("A test dataset".to_string()),
            source_agent: "TestAgent".to_string(),
            relevance_score: 0.8,
            ..DatasetResult::default()
        }];
        let content = build_dataset_jsonld_itemlist(&results);
        assert_eq!(content["@type"], "ItemList");
        assert_eq!(content["numberOfItems"], 1);
        let items = content["itemListElement"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["item"]["name"], "test_dataset");
    }

    #[test]
    fn extract_results_from_empty_content_returns_empty_vec() {
        let content = json!({ "result": {} });
        let results = extract_results_from_handshake(&content, "TestAgent", "did:key:z6Mk");
        assert!(results.is_empty());
    }

    #[test]
    fn build_empty_itemlist_returns_zero_count() {
        let results = build_dataset_jsonld_itemlist(&[]);
        assert_eq!(results["numberOfItems"], 0);
        assert!(results["itemListElement"].as_array().unwrap().is_empty());
    }
}
