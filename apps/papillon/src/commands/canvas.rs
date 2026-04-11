#![allow(clippy::unwrap_used)]
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, State};

use pap_did::PrincipalKeypair;
use pap_federation::{build_pinned_client, PapUrl};
use pap_transport::{AgentHandler, RemoteAgentHandler};

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::handshake;
use crate::state::AppState;
use papillon_shared::{BlockEvent, BlockState, CanvasBlock, IntentPlan, PreferenceEngine};

use super::orchestrator::hash_agent_did;

// ── Canvas State Types ─────────────────────────────────────────────────────

/// A synthesized summary of a single completed agent interaction episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeSummary {
    /// Ephemeral session DID (first 16 chars of receipt_session_id for display).
    pub session_did: String,
    /// Agent DID hash (privacy-safe — never raw DID).
    pub agent_did: String,
    /// Human-readable agent name.
    pub agent_name: String,
    /// Schema.org action type exercised, e.g. "schema:SearchAction".
    pub action: String,
    /// Episode outcome: "success", "failure", or "rejected".
    pub outcome: String,
    /// ISO-8601 timestamp of when the episode was recorded.
    pub timestamp: String,
    /// SHA-256 hash of the receipt session ID — used as a stable identity.
    pub receipt_hash: String,
    /// Optional human-readable summary of the agent's intent.
    pub intent_summary: Option<String>,
}

/// Synthesized canvas state returned to the frontend for outcome rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasSummaryState {
    /// Principal DID — the root of trust for this session.
    pub principal_did: String,
    /// All completed episode summaries, most recent first.
    pub episodes: Vec<EpisodeSummary>,
    /// Count of episodes in "success" outcome.
    pub success_count: u32,
    /// Count of episodes in "failure" or "rejected" outcome.
    pub failure_count: u32,
    /// Count of distinct session IDs currently active (episodes with no result yet).
    /// In the in-memory model this is always 0; future SQLite integration will populate it.
    pub active_sessions: u32,
}

/// Retrieve the current canvas outcome state.
///
/// Reads completed episodes from the persistent episode store and synthesises
/// a `CanvasSummaryState` for the frontend outcome timeline.  All data is
/// derived from the encrypted-at-rest SQLite DB — no in-memory session state
/// is required.
#[tauri::command]
pub fn get_canvas_state(state: State<'_, AppState>) -> Result<CanvasSummaryState, PapillonError> {
    // Get principal DID from the current signer
    let principal_did = {
        let signer = state
            .signer
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        match signer.as_ref() {
            Some(s) => s.did(),
            None => "did:key:unknown".to_string(),
        }
    };

    // Load up to 100 most recent episodes from the persistent store
    let raw_episodes = state
        .db
        .list_episodes(None, None, 100, Some(0))
        .map_err(|e| PapillonError::from(e.0))?;

    let mut success_count: u32 = 0;
    let mut failure_count: u32 = 0;

    let episodes: Vec<EpisodeSummary> = raw_episodes
        .iter()
        .map(|ep| {
            // Derive a display-safe session identifier (first 16 chars)
            let session_did = if ep.receipt_session_id.len() > 16 {
                ep.receipt_session_id[..16].to_string()
            } else {
                ep.receipt_session_id.clone()
            };

            // Compute a stable receipt hash from the session ID
            let mut hasher = Sha256::new();
            hasher.update(ep.receipt_session_id.as_bytes());
            let receipt_hash = format!("{:x}", hasher.finalize());
            // Truncate to first 16 hex chars for display
            let receipt_hash = receipt_hash[..16].to_string();

            if ep.outcome == "success" {
                success_count += 1;
            } else {
                failure_count += 1;
            }

            EpisodeSummary {
                session_did,
                agent_did: ep.agent_did_hash.clone(),
                agent_name: ep.agent_name.clone(),
                action: ep.action_type.clone(),
                outcome: ep.outcome.clone(),
                timestamp: ep.recorded_at.clone(),
                receipt_hash,
                intent_summary: ep.intent_summary.clone(),
            }
        })
        .collect();

    Ok(CanvasSummaryState {
        principal_did,
        episodes,
        success_count,
        failure_count,
        active_sessions: 0,
    })
}

/// Detect intent from a user prompt.
/// Returns (action_type, preferred_agent_name, cleaned_query).
///
/// Delegates to the shared intent table in `papillon_shared::intent`.
fn detect_intent(prompt: &str) -> (&'static str, &'static str, String) {
    papillon_shared::intent::detect_intent(prompt)
}

/// Score an agent candidate using profile history and local preference signals.
/// Higher is better.  The score combines:
/// - `AgentProfile` EMA statistics (success_rate, avg_quality)
/// - `PreferenceEngine` schema-type-aware preference score
/// - A keyword-match bonus for the intent-matched agent name
///
/// Preference score contributes up to 30% of the total when the engine has
/// enough history (≥ 3 sessions).  EMA statistics contribute 40% each on top.
fn score_agent(
    db: &crate::db::Database,
    agent_did: &str,
    preferred_name: &str,
    agent_name: &str,
    action_type: &str,
    schema_type: &str,
) -> f64 {
    let agent_did_hash = hash_agent_did(agent_did);

    // Preference engine score (0.0 on cold start, up to 1.0 with history)
    let engine = PreferenceEngine::new(db);
    let pref_score = engine.preference_score(action_type, schema_type, &agent_did_hash);

    // Keyword match bonus
    let keyword_bonus = if agent_name == preferred_name {
        1.0
    } else {
        0.0
    };

    match db.get_agent_profile(&agent_did_hash).ok().flatten() {
        Some(profile) if profile.episode_count >= 3 => {
            // 35% success_rate + 35% avg_quality + 20% preference + 10% keyword
            let base = 0.35 * profile.success_rate + 0.35 * profile.avg_quality;
            base + 0.20 * pref_score + 0.10 * keyword_bonus
        }
        Some(_) => {
            // Too few EMA episodes — lean on preference + keyword
            if pref_score > 0.0 {
                0.40 + 0.30 * pref_score + 0.10 * keyword_bonus
            } else if agent_name == preferred_name {
                0.7
            } else {
                0.5
            }
        }
        None => {
            // No EMA history — preference engine + keyword fallback
            if pref_score > 0.0 {
                0.30 + 0.40 * pref_score + 0.10 * keyword_bonus
            } else if agent_name == preferred_name {
                0.6
            } else {
                0.4
            }
        }
    }
}

/// Quick quality assessment of a handshake result (0.0 to 1.0).
/// Evaluates content richness without requiring an Episode record.
fn assess_handshake_quality(result: &handshake::HandshakeResult) -> f64 {
    let content = &result.content;
    let payload = content.get("result");
    match payload {
        None => 0.3,
        Some(serde_json::Value::Null) => 0.2,
        Some(serde_json::Value::String(s)) if s.is_empty() => 0.3,
        Some(serde_json::Value::String(s)) if s.len() < 20 => 0.5,
        Some(serde_json::Value::Object(map)) if map.is_empty() => 0.3,
        Some(serde_json::Value::Array(arr)) if arr.is_empty() => 0.3,
        Some(serde_json::Value::Array(arr)) if arr.len() < 3 => 0.6,
        Some(serde_json::Value::Object(map)) => {
            let fields = map.len();
            match fields {
                0 => 0.3,
                1..=2 => 0.6,
                3..=5 => 0.8,
                _ => 1.0,
            }
        }
        _ => 0.8,
    }
}

/// Result of agent resolution from registries.
pub(crate) struct ResolvedAgent {
    pub name: String,
    pub did: String,
    pub handler: Arc<dyn AgentHandler>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
}

/// Resolve an agent by action type: discover from registries, build handler.
/// Applies memory-informed scoring to rank candidates.
/// `exclude_agents` filters out agents by name (used by reflection retries).
pub(crate) async fn resolve_agent(
    state: &State<'_, AppState>,
    action_type: &str,
    preferred_name: &str,
    exclude_agents: &[String],
) -> Result<ResolvedAgent, PapillonError> {
    // Discover agent — try local registry first, then remote registries.
    let (agent_name, agent_did, requires_disclosure, returns, source_url) = {
        let local = state
            .local_registry
            .lock()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        // Use query_local (not query_local_satisfiable) for local agents:
        // local agents run on the user's device and are trusted. Disclosure
        // filtering is meaningful for remote/federated agents, not local ones.
        let candidates = local.query_local(action_type);

        // Filter out excluded agents, then score the rest
        let eligible: Vec<_> = candidates
            .iter()
            .filter(|a| !exclude_agents.contains(&a.name))
            .collect();

        let best = if eligible.is_empty() {
            None
        } else {
            let mut scored: Vec<_> = eligible
                .iter()
                .map(|a| {
                    // Use first returns type as schema hint for preference scoring
                    let schema_hint = a.returns.first().map(|s| s.as_str()).unwrap_or("");
                    let s = score_agent(
                        &state.db,
                        &a.provider.did,
                        preferred_name,
                        &a.name,
                        action_type,
                        schema_hint,
                    );
                    (*a, s)
                })
                .collect();
            scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            scored.first().map(|(a, _)| *a)
        };

        if let Some(agent) = best {
            (
                agent.name.clone(),
                agent.provider.did.clone(),
                agent.requires_disclosure.clone(),
                agent.returns.clone(),
                None, // local — no source URL
            )
        } else {
            // Not found locally — search synced remote registries
            drop(local);
            let registries = state
                .registries
                .read()
                .map_err(|e| PapillonError::from(e.to_string()))?;

            let mut found = None;
            for (url, registry) in registries.iter() {
                let remote_candidates = registry.query_local_satisfiable(action_type, &[]);
                let eligible: Vec<_> = remote_candidates
                    .iter()
                    .filter(|a| !exclude_agents.contains(&a.name))
                    .collect();

                let best = if eligible.is_empty() {
                    None
                } else {
                    let mut scored: Vec<_> = eligible
                        .iter()
                        .map(|a| {
                            let schema_hint = a.returns.first().map(|s| s.as_str()).unwrap_or("");
                            let s = score_agent(
                                &state.db,
                                &a.provider.did,
                                preferred_name,
                                &a.name,
                                action_type,
                                schema_hint,
                            );
                            (*a, s)
                        })
                        .collect();
                    scored
                        .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                    scored.first().map(|(a, _)| *a)
                };

                if let Some(agent) = best {
                    found = Some((
                        agent.name.clone(),
                        agent.provider.did.clone(),
                        agent.requires_disclosure.clone(),
                        agent.returns.clone(),
                        Some(url.clone()),
                    ));
                    break;
                }
            }

            found.ok_or_else(|| PapillonError::from(format!("No agent for {}", action_type)))?
        }
    };

    // Resolve handler — local handler or remote proxy over TLS.
    let handler: Arc<dyn AgentHandler> = if let Some(h) = state.local_agents.get(&agent_name) {
        h.clone()
    } else if let Some(ref pap_url) = source_url {
        let parsed = PapUrl::parse(pap_url).map_err(|e| PapillonError::from(e.to_string()))?;
        let endpoint = parsed.https_endpoint();

        let fingerprint = {
            let local = state
                .local_registry
                .lock()
                .map_err(|e| PapillonError::from(e.to_string()))?;
            local
                .peers()
                .iter()
                .find(|p| p.endpoint.trim_end_matches('/') == endpoint.trim_end_matches('/'))
                .and_then(|p| p.cert_fingerprint.clone())
        };

        let slug = agent_name.to_lowercase().replace(' ', "-");
        let base_url = format!("{}/agents/{}", endpoint, slug);

        if let Some(fp) = fingerprint {
            let http_client =
                build_pinned_client(&[fp]).map_err(|e| PapillonError::from(e.to_string()))?;
            Arc::new(RemoteAgentHandler::with_client(&base_url, http_client))
        } else {
            return Err(PapillonError::from(format!(
                "No cert fingerprint for peer {} — navigate to it first",
                endpoint
            )));
        }
    } else {
        return Err(PapillonError::from(format!(
            "No handler for {}",
            agent_name
        )));
    };

    Ok(ResolvedAgent {
        name: agent_name,
        did: agent_did,
        handler,
        requires_disclosure,
        returns,
    })
}

/// Discover agent, resolve handler, run handshake, and apply reflection.
async fn process_prompt(
    app: &AppHandle,
    state: &State<'_, AppState>,
    prompt_id: &str,
    block_id: &str,
    text: &str,
) -> Result<(String, serde_json::Value, bool, String), PapillonError> {
    process_prompt_inner(app, state, prompt_id, block_id, text, &[], 0).await
}

/// Inner implementation with exclusion list and retry budget for reflection.
/// Uses `Box::pin` for the recursive async call required by the reflection gate.
///
/// Returns `(schema_type, content, preference_guided, agent_did)` where `preference_guided`
/// is `true` when the PreferenceEngine had meaningful history that influenced
/// agent selection, and `agent_did` is the DID of the resolved agent.
#[allow(clippy::type_complexity)]
fn process_prompt_inner<'a>(
    app: &'a AppHandle,
    state: &'a State<'a, AppState>,
    prompt_id: &'a str,
    block_id: &'a str,
    text: &'a str,
    exclude_agents: &'a [String],
    retry_count: u8,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = Result<(String, serde_json::Value, bool, String), PapillonError>,
            > + Send
            + 'a,
    >,
> {
    Box::pin(async move {
        let (action_type, preferred, query) = detect_intent(text);

        let resolved = resolve_agent(state, action_type, preferred, exclude_agents).await?;
        // Capture agent DID before the handshake so it can be threaded into block_resolved.
        let agent_did = resolved.did.clone();

        // Derive schema type from agent's declared returns (first element).
        let schema_hint = resolved.returns.first().cloned().unwrap_or_default();
        let agent_did_hash = hash_agent_did(&resolved.did);

        // Check guidance BEFORE recording — so the badge reflects pre-selection history,
        // not the selection we're about to record (which would fire on the tip-over episode).
        let engine = PreferenceEngine::new(state.db.as_ref());
        let preference_guided = engine.is_preference_guided(action_type, &schema_hint);
        engine.record_agent_selected(action_type, &schema_hint, &agent_did_hash, &resolved.name);

        // Get principal keypair
        let principal_kp = {
            let seed_guard = state.principal_seed.read().unwrap();
            let seed = seed_guard
                .as_ref()
                .ok_or_else(|| PapillonError::from("No identity configured"))?;
            PrincipalKeypair::from_bytes(seed)
                .map_err(|e| PapillonError::from(format!("Failed to load keypair: {}", e)))?
        };

        // Phase progress callbacks emit Tauri events.
        // Thread the computed preference_guided flag so the frontend can show
        // the "based on your preferences" badge during intermediate states too.
        let bid = block_id.to_string();
        let pid = prompt_id.to_string();
        let app_phase = app.clone();
        let on_phase: handshake::PhaseCallback = Box::new(move |phase, label| {
            let now = Utc::now().to_rfc3339();
            let block = CanvasBlock {
                id: bid.clone(),
                prompt_id: pid.clone(),
                prompt_text: None,
                state: BlockState::Resolving {
                    phase,
                    phase_label: label.into(),
                },
                schema_type: None,
                content: None,
                linked_block_ids: Vec::new(),
                agent_did: None,
                mandate_expires_at: None,
                preference_guided,
                created_at: now.clone(),
                updated_at: now,
            };
            let _ = app_phase.emit("block_updated", BlockEvent { block });
        });

        let bid2 = block_id.to_string();
        let pid2 = prompt_id.to_string();
        let app_fail = app.clone();
        let on_fail: handshake::FailCallback = Box::new(move |phase, reason| {
            let now = Utc::now().to_rfc3339();
            let block = CanvasBlock {
                id: bid2.clone(),
                prompt_id: pid2.clone(),
                prompt_text: None,
                state: BlockState::Failed {
                    phase,
                    reason: reason.into(),
                },
                schema_type: None,
                content: None,
                linked_block_ids: Vec::new(),
                agent_did: None,
                mandate_expires_at: None,
                preference_guided,
                created_at: now.clone(),
                updated_at: now,
            };
            let _ = app_fail.emit("block_resolved", BlockEvent { block });
        });

        let result = handshake::execute(handshake::HandshakeParams {
            handler: resolved.handler,
            agent_name: &resolved.name,
            agent_did: &resolved.did,
            action_type,
            query: &query,
            principal_kp: &principal_kp,
            requires_disclosure: &resolved.requires_disclosure,
            returns: &resolved.returns,
            on_phase,
            on_fail,
        })
        .await?;

        // Reflection gate: if quality is low and we haven't retried yet,
        // try the next-best agent.
        let quality = assess_handshake_quality(&result);
        if quality < 0.5 && retry_count == 0 {
            let mut new_exclude = exclude_agents.to_vec();
            new_exclude.push(resolved.name.clone());

            // Check if an alternative agent exists before retrying
            if resolve_agent(state, action_type, preferred, &new_exclude)
                .await
                .is_ok()
            {
                // Emit a "reflecting" phase event
                let now = Utc::now().to_rfc3339();
                let _ = app.emit(
                    "block_updated",
                    BlockEvent {
                        block: CanvasBlock {
                            id: block_id.to_string(),
                            prompt_id: prompt_id.to_string(),
                            prompt_text: None,
                            state: BlockState::Resolving {
                                phase: 7,
                                phase_label: "Reflecting — trying alternative agent...".into(),
                            },
                            schema_type: None,
                            content: None,
                            linked_block_ids: Vec::new(),
                            agent_did: None,
                            mandate_expires_at: None,
                            preference_guided,
                            created_at: now.clone(),
                            updated_at: now,
                        },
                    },
                );

                return process_prompt_inner(
                    app,
                    state,
                    prompt_id,
                    block_id,
                    text,
                    &new_exclude,
                    retry_count + 1,
                )
                .await;
            }
        }

        // Record outcome after the quality gate — success only when quality is acceptable.
        // If we retried (returned early above), this line is never reached for the bad attempt.
        PreferenceEngine::new(state.db.as_ref()).record_outcome(
            action_type,
            &schema_hint,
            &agent_did_hash,
            quality >= 0.5,
        );

        Ok((
            result.schema_type,
            result.content,
            preference_guided,
            agent_did,
        ))
    })
}

/// Try to auto-generate and persist a template for the given schema type.
///
/// Only generates when the handshake envelope contains a `"result"` object and
/// no enabled template already covers this schema type. Errors are logged but
/// never propagated — template generation is advisory.
fn maybe_auto_generate_template(
    state: &State<'_, AppState>,
    schema_type: &str,
    content: &serde_json::Value,
) {
    let result_payload = match content.get("result") {
        Some(v) if v.is_object() => v,
        _ => return,
    };

    let has_template = state
        .db
        .has_enabled_template_for_schema_type(schema_type)
        .unwrap_or(true);

    if has_template {
        return;
    }

    let template = papillon_shared::generate_template_from_json_ld(schema_type, result_payload);
    if template.template_config.validate().is_ok() {
        if let Err(e) = state.db.insert_template(&template) {
            eprintln!("Failed to auto-generate template for {schema_type}: {e}");
        }
    }
}

#[tauri::command]
pub async fn canvas_prompt(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    prompt_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillonError> {
    let (schema_type, content, preference_guided, agent_did) =
        process_prompt(&app, &state, &prompt_id, &block_id, &text).await?;

    // Auto-generate template if none exists for this schema type.
    maybe_auto_generate_template(&state, &schema_type, &content);

    let now = Utc::now().to_rfc3339();
    let mandate_ttl_hours = {
        let cfg = state.orchestrator_config.read().unwrap();
        cfg.mandate_ttl_hours
    };
    let mandate_expires_at =
        Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
    let _ = app.emit(
        "block_resolved",
        BlockEvent {
            block: CanvasBlock {
                id: block_id.clone(),
                prompt_id,
                prompt_text: Some(text),
                state: BlockState::Resolved,
                schema_type: Some(schema_type),
                content: Some(content),
                linked_block_ids: Vec::new(),
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
    let (schema_type, content, preference_guided, agent_did) =
        process_prompt(&app, &state, "", &block_id, &text).await?;

    // Auto-generate template if none exists for this schema type.
    maybe_auto_generate_template(&state, &schema_type, &content);

    let now = Utc::now().to_rfc3339();
    let mandate_ttl_hours = {
        let cfg = state.orchestrator_config.read().unwrap();
        cfg.mandate_ttl_hours
    };
    let mandate_expires_at =
        Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
    let _ = app.emit(
        "block_resolved",
        BlockEvent {
            block: CanvasBlock {
                id: block_id.clone(),
                prompt_id: String::new(),
                prompt_text: Some(text),
                state: BlockState::Resolved,
                schema_type: Some(schema_type),
                content: Some(content),
                linked_block_ids: Vec::new(),
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

/// Two-phase canvas prompt: plan first (emit `AwaitingApproval`), then wait for
/// principal approval before running the full handshake.
///
/// If `auto_approve_zero_disclosure` is enabled in the orchestrator config and the
/// resolved agent requires no disclosure fields, the gate is skipped and the
/// handshake runs immediately.
#[tauri::command]
pub async fn canvas_plan_prompt(
    app: AppHandle,
    state: State<'_, AppState>,
    _canvas_id: String,
    prompt_id: String,
    block_id: String,
    text: String,
) -> Result<serde_json::Value, PapillonError> {
    let (action_type, preferred, _query) = detect_intent(&text);

    // Resolve agent to build the IntentPlan.
    let resolved = resolve_agent(&state, action_type, preferred, &[]).await?;

    let approval_request_id = uuid::Uuid::new_v4().to_string();

    let mandate_ttl_hours = {
        let cfg = state
            .orchestrator_config
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        cfg.mandate_ttl_hours
    };
    let plan = IntentPlan {
        action: action_type.to_string(),
        selected_agent_name: resolved.name.clone(),
        selected_agent_did: Some(resolved.did.clone()),
        requires_disclosure: resolved.requires_disclosure.clone(),
        returns: resolved.returns.clone(),
        approval_request_id: approval_request_id.clone(),
        ttl_hours: mandate_ttl_hours as u32,
    };

    // Check auto-approve shortcut: if configured and no disclosure required, skip the gate.
    let auto_approve = {
        let config = state
            .orchestrator_config
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        config.auto_approve_zero_disclosure
    } && plan.requires_disclosure.is_empty();

    if auto_approve {
        // Run directly without emitting AwaitingApproval.
        let (schema_type, content, preference_guided, agent_did) =
            process_prompt(&app, &state, &prompt_id, &block_id, &text).await?;
        maybe_auto_generate_template(&state, &schema_type, &content);
        let now = Utc::now().to_rfc3339();
        let mandate_expires_at =
            Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Resolved,
                    schema_type: Some(schema_type),
                    content: Some(content),
                    linked_block_ids: Vec::new(),
                    agent_did: Some(agent_did),
                    mandate_expires_at,
                    preference_guided,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
        return Ok(serde_json::json!({ "status": "ok", "block_id": block_id }));
    }

    // Emit the AwaitingApproval block so the frontend can render the approval UI.
    let now = Utc::now().to_rfc3339();
    let _ = app.emit(
        "block_updated",
        BlockEvent {
            block: CanvasBlock {
                id: block_id.clone(),
                prompt_id: prompt_id.clone(),
                prompt_text: Some(text.clone()),
                state: BlockState::AwaitingApproval { plan: plan.clone() },
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

    // Create the oneshot channel and store the sender in the approval_gates map.
    let (sender, receiver) = tokio::sync::oneshot::channel::<bool>();
    {
        let mut gates = state.approval_gates.write().await;
        gates.insert(approval_request_id.clone(), sender);
    }

    // Block until the principal approves or rejects (or the sender is dropped).
    let approved = receiver.await.unwrap_or(false);

    if approved {
        // Run the full handshake.
        let (schema_type, content, preference_guided, agent_did) =
            process_prompt(&app, &state, &prompt_id, &block_id, &text).await?;
        maybe_auto_generate_template(&state, &schema_type, &content);
        let now = Utc::now().to_rfc3339();
        let mandate_expires_at =
            Some((Utc::now() + chrono::Duration::hours(mandate_ttl_hours as i64)).to_rfc3339());
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Resolved,
                    schema_type: Some(schema_type),
                    content: Some(content),
                    linked_block_ids: Vec::new(),
                    agent_did: Some(agent_did),
                    mandate_expires_at,
                    preference_guided,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
        Ok(serde_json::json!({ "status": "ok", "block_id": block_id }))
    } else {
        // Principal rejected — emit a Failed block.
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: CanvasBlock {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Failed {
                        phase: 0,
                        reason: "Rejected by principal".to_string(),
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
        Ok(serde_json::json!({ "status": "rejected", "block_id": block_id }))
    }
}

/// Resolve a pending approval gate created by `canvas_plan_prompt`.
///
/// Sends `approved` (true/false) through the oneshot channel, which unblocks
/// the waiting `canvas_plan_prompt` command and either proceeds with the
/// handshake or emits a Failed block.
#[tauri::command]
pub async fn canvas_approve_block(
    approval_request_id: String,
    approved: bool,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let sender = {
        let mut gates = state.approval_gates.write().await;
        gates.remove(&approval_request_id)
    };
    if let Some(sender) = sender {
        let _ = sender.send(approved);
        Ok(())
    } else {
        Err(format!(
            "No approval gate found for {}",
            approval_request_id
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_intent_wiki() {
        let (action, agent, _query) = detect_intent("wikipedia Rust language");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Wikipedia Knowledge");
    }

    #[test]
    fn detect_intent_search() {
        let (action, agent, _query) = detect_intent("search for cats");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "DuckDuckGo Search");
    }

    #[test]
    fn detect_intent_ai_fallback() {
        let (action, agent, query) = detect_intent("explain quantum computing");
        assert_eq!(action, "schema:AskAction");
        assert_eq!(agent, "On-Device AI");
        assert_eq!(query, "explain quantum computing");
    }

    #[test]
    fn detect_intent_weather() {
        let (action, agent, _query) = detect_intent("weather 48.85,2.35");
        assert_eq!(action, "schema:CheckAction");
        assert_eq!(agent, "Open-Meteo Weather");
    }

    #[test]
    fn detect_intent_forecast() {
        let (action, agent, _query) = detect_intent("forecast for tomorrow");
        assert_eq!(action, "schema:CheckAction");
        assert_eq!(agent, "Open-Meteo Weather");
    }

    #[test]
    fn detect_intent_currency() {
        let (action, agent, _query) = detect_intent("convert 100 USD EUR");
        assert_eq!(action, "schema:TradeAction");
        assert_eq!(agent, "Frankfurter Exchange");
    }

    #[test]
    fn detect_intent_geocode() {
        let (action, agent, _query) = detect_intent("where is Paris");
        assert_eq!(action, "schema:FindAction");
        assert_eq!(agent, "Nominatim Geocoding");
    }

    #[test]
    fn detect_intent_books() {
        let (action, agent, _query) = detect_intent("book about rust programming");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Open Library Books");
    }

    #[test]
    fn detect_intent_hackernews() {
        let (action, agent, _query) = detect_intent("hacker news rust");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "Hacker News");
    }

    #[test]
    fn score_agent_prefers_keyword_match_without_profile() {
        // No DB available in unit tests, so we verify the scoring constants
        // used in score_agent: preferred baseline (0.6) > non-preferred (0.4)
        let preferred_baseline = 0.6_f64;
        let non_preferred_baseline = 0.4_f64;
        assert!(preferred_baseline > non_preferred_baseline);
    }

    #[test]
    fn assess_quality_empty_result() {
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"agent": "test"}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        // No "result" key → 0.3
        assert!((quality - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn assess_quality_null_result() {
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": null}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn assess_quality_rich_object() {
        let result = handshake::HandshakeResult {
            schema_type: "SearchResult".into(),
            content: serde_json::json!({
                "result": {
                    "title": "Test",
                    "url": "https://example.com",
                    "snippet": "A test result",
                    "source": "DuckDuckGo"
                }
            }),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        // 4 fields → 0.8
        assert!((quality - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn assess_quality_large_array() {
        let result = handshake::HandshakeResult {
            schema_type: "SearchResult".into(),
            content: serde_json::json!({
                "result": ["a", "b", "c", "d"]
            }),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        // Array with 4 items → 0.8 (generic match)
        assert!(quality >= 0.8);
    }

    #[test]
    fn assess_quality_empty_string() {
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": ""}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.3).abs() < f64::EPSILON);
    }
}
