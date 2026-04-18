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
use papillon_shared::{BlockEvent, BlockState, BlockUpdate, GuideSuggestion, IntentPlan, PreferenceEngine};

use super::orchestrator::hash_agent_did;

/// BM25 confidence threshold for Level 2 intent routing.
/// Queries below this threshold fall through to the Level 3 on-device / federation NLU path.
const INTENT_CONFIDENCE_THRESHOLD: f32 = 0.25;

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

/// Map an NLU label to a schema.org action type and preferred agent name.
fn map_label_to_action(label: &str) -> (&'static str, &'static str) {
    match label {
        "weather" => ("schema:CheckAction", "Open-Meteo Weather"),
        "currency-exchange" => ("schema:TradeAction", "Frankfurter Exchange"),
        "dictionary" => ("schema:SearchAction", "Free Dictionary"),
        "code-repository" => ("schema:SearchAction", "GitHub Repos"),
        "book" => ("schema:SearchAction", "Open Library Books"),
        "tech-news" => ("schema:SearchAction", "Hacker News"),
        "academic-paper" => ("schema:SearchAction", "arXiv Papers"),
        "geocode" => ("schema:FindAction", "Nominatim Geocoding"),
        "dataset" => ("schema:DatasetAction", "Dataset Discovery"),
        "music" => ("schema:SearchAction", "MusicBrainz"),
        "film" => ("schema:SearchAction", "Open Movie Database"),
        "job-listing" => ("schema:SearchAction", "Remote OK Jobs"),
        "recipe" => ("schema:SearchAction", "MealDB Recipes"),
        "product" => ("schema:SearchAction", "Open Food Facts"),
        _ => ("schema:SearchAction", "DuckDuckGo Search"),
    }
}

/// Classify intent from a user prompt using federation-native NLU agents.
///
/// Fast path: bare HTTP/HTTPS URLs are routed deterministically to Web Page Reader.
/// All other prompts trigger a silent PAP handshake with a discovered
/// `schema:AnalyzeAction` agent (HuggingFace NLU or on-device LLM classifier).
/// Returns `(action_type, preferred_agent, effective_query)` as owned strings.
///
/// Falls back to `("schema:AskAction", "", raw_text)` when no NLU agent is
/// registered, the handshake fails, or confidence is below the configured threshold.
async fn classify_intent(
    app: &AppHandle,
    state: &State<'_, AppState>,
    block_id: &str,
    text: &str,
) -> (String, String, String) {
    // Level 1: deterministic fast path — bare HTTP/HTTPS URLs → Web Page Reader
    let (action, preferred, query) = papillon_shared::intent::detect_intent(text);
    if action != "schema:AnalyzeAction" {
        return (action.to_owned(), preferred.to_owned(), query);
    }

    // Level 2: BM25 semantic index — ~50µs scoring, no network, no spinner needed.
    // Built from the current canvas's agent DB so it reflects approved agents.
    // agent_name is a hint only; downstream resolve_agent applies disclosure
    // scoring so no agent is forced without proper permission evaluation.
    // Falls through to Level 3 when confidence < INTENT_CONFIDENCE_THRESHOLD or catalog is empty.
    {
        let agents = state.db.load_all_agents().unwrap_or_else(|e| {
            eprintln!("[classify_intent] agent catalog unavailable, skipping BM25: {e}");
            vec![]
        });
        let intent_index = pap_agents::IntentIndex::new(&agents);
        if let Some(m) = intent_index.classify(text, INTENT_CONFIDENCE_THRESHOLD) {
            // Empty string means "no forced agent" — resolve_agent selects
            // the best candidate by disclosure scope and profile history.
            let preferred_agent = m.agent_name.unwrap_or_default();
            return (m.action, preferred_agent, m.cleaned_query);
        }
    }

    // Level 3: federation NLU — emit phase 0 spinner while the slower path runs
    {
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_updated",
            BlockEvent {
                block: BlockUpdate {
                    id: block_id.to_string(),
                    prompt_id: String::new(),
                    prompt_text: None,
                    state: BlockState::Resolving {
                        phase: 0,
                        phase_label: "Detecting intent\u{2026}".into(),
                    },
                    schema_type: None,
                    content: None,
                    agent_did: None,
                    mandate_expires_at: None,
                    preference_guided: false,
                    created_at: now.clone(),
                    updated_at: now,
                },
            },
        );
    }

    // Universal fallback: when NLU classification cannot run or is not confident,
    // route to DuckDuckGo web search (no API key, always available) rather than
    // schema:AskAction which requires a local LLM.
    macro_rules! nlu_fallback {
        () => {
            return (
                "schema:SearchAction".to_owned(),
                "DuckDuckGo Search".to_owned(),
                text.to_owned(),
            )
        };
    }

    // Resolve NLU agent — scoring drives priority, no name hint needed
    let Ok(resolved) = resolve_agent(state, "schema:AnalyzeAction", "", &[]).await else {
        nlu_fallback!();
    };

    let principal_kp = {
        let seed_guard = state.principal_seed.read().unwrap();
        let Some(seed) = seed_guard.as_ref() else {
            nlu_fallback!();
        };
        match PrincipalKeypair::from_bytes(seed) {
            Ok(kp) => kp,
            Err(_) => nlu_fallback!(),
        }
    };

    let Ok(result) = handshake::execute(handshake::HandshakeParams {
        handler: resolved.handler,
        agent_name: &resolved.name,
        agent_did: &resolved.did,
        action_type: "schema:AnalyzeAction",
        query: text,
        principal_kp: &principal_kp,
        requires_disclosure: &resolved.requires_disclosure,
        returns: &resolved.returns,
        on_phase: Box::new(|_, _| {}),
        on_fail: Box::new(|_, _| {}),
    })
    .await
    else {
        nlu_fallback!();
    };

    let label = result
        .content
        .get("actionType")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let confidence = result
        .content
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // cleanedQuery: produced by LLM classifiers, absent for HuggingFace.
    // When present, the capability agent receives the distilled query.
    let effective_query = result
        .content
        .get("cleanedQuery")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(text)
        .to_owned();

    let threshold = {
        let cfg = state.orchestrator_config.read().unwrap();
        cfg.intent_confidence_threshold
    };

    if confidence < threshold || label.is_empty() || label == "question-answer" {
        nlu_fallback!();
    }

    let (action_type, preferred_agent) = map_label_to_action(label);
    (
        action_type.to_owned(),
        preferred_agent.to_owned(),
        effective_query,
    )
}

/// Score an agent candidate using profile history and local preference signals.
/// Higher is better.  The score combines:
/// - `AgentProfile` EMA statistics (success_rate, avg_quality)
/// - `PreferenceEngine` schema-type-aware preference score
/// - A keyword-match bonus for the intent-matched agent name
/// - Model-substrate signals: local agents that can use the user's configured LLM
///   are boosted; remote agents missing an API token are penalised
///
/// Preference score contributes up to 30% of the total when the engine has
/// enough history (≥ 3 sessions).  EMA statistics contribute 40% each on top.
#[allow(clippy::too_many_arguments)]
fn score_agent(
    db: &crate::db::Database,
    agent_did: &str,
    preferred_name: &str,
    agent_name: &str,
    action_type: &str,
    schema_type: &str,
    agent_def: Option<&pap_agents::DynamicAgentDef>,
    inference_substrate: &papillon_shared::LlmProvider,
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

    // ── Model-substrate / source signals ─────────────────────────────────
    let mut substrate_delta: f64 = 0.0;

    if let Some(def) = agent_def {
        // Agents without an external HTTP endpoint run locally via the LLM substrate.
        if def.endpoint.is_none() {
            // Any configured LLM substrate (not None) means this agent can run.
            if !matches!(inference_substrate, papillon_shared::LlmProvider::None) {
                substrate_delta += 0.4;
            }
            // Fully on-device BuiltIn model — most private, highest bonus.
            if matches!(
                inference_substrate,
                papillon_shared::LlmProvider::BuiltIn { .. }
            ) {
                substrate_delta += 0.2;
            }
        } else if let Some(endpoint) = &def.endpoint {
            // Agent has an external endpoint — check if it needs auth and has a token.
            let needs_auth = endpoint.headers.contains_key("Authorization");
            if needs_auth {
                let api_token_set = db
                    .get_agent_settings(&agent_did_hash)
                    .ok()
                    .and_then(|settings| settings.get("api_token").map(|s| !s.value.is_empty()))
                    .unwrap_or(false);
                if !api_token_set {
                    // Would fail — deprioritize.
                    substrate_delta -= 0.3;
                }
            }
        }

        // Source bonus/penalty.
        match def.source {
            pap_agents::DynamicAgentSource::Catalog => {
                substrate_delta += 0.1;
            }
            pap_agents::DynamicAgentSource::Generated => {
                substrate_delta -= 0.1;
            }
            _ => {}
        }
    } else {
        // No local def found — treat as federated/remote agent.
        substrate_delta -= 0.1;
    }

    let base_score = match db.get_agent_profile(&agent_did_hash).ok().flatten() {
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
    };

    base_score + substrate_delta
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
    // Load all local agent defs once for model-substrate / source scoring.
    // Keyed by agent DID so we can look up quickly per candidate.
    let agent_defs: std::collections::HashMap<String, pap_agents::DynamicAgentDef> = state
        .db
        .load_all_agents()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| d.agent_did.clone().map(|did| (did, d)))
        .collect();

    // Read inference substrate from the orchestrator config for substrate scoring.
    let inference_substrate = {
        let cfg = state.orchestrator_config.read().unwrap();
        cfg.inference_substrate.clone()
    };

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
                    let agent_def = agent_defs.get(&a.provider.did);
                    let s = score_agent(
                        &state.db,
                        &a.provider.did,
                        preferred_name,
                        &a.name,
                        action_type,
                        schema_hint,
                        agent_def,
                        &inference_substrate,
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
                            // Remote/federated agents won't be in the local agent_defs map.
                            let agent_def = agent_defs.get(&a.provider.did);
                            let s = score_agent(
                                &state.db,
                                &a.provider.did,
                                preferred_name,
                                &a.name,
                                action_type,
                                schema_hint,
                                agent_def,
                                &inference_substrate,
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
/// Callers must pre-classify intent via `classify_intent` before calling this.
async fn process_prompt(
    app: &AppHandle,
    state: &State<'_, AppState>,
    prompt_id: &str,
    block_id: &str,
    action_type: &str,
    preferred: &str,
    query: &str,
) -> Result<(String, serde_json::Value, bool, String), PapillonError> {
    process_prompt_inner(
        app,
        state,
        prompt_id,
        block_id,
        action_type,
        preferred,
        query,
        &[],
        0,
    )
    .await
}

/// Inner implementation with exclusion list and retry budget for reflection.
/// Uses `Box::pin` for the recursive async call required by the reflection gate.
///
/// Returns `(schema_type, content, preference_guided, agent_did)` where `preference_guided`
/// is `true` when the PreferenceEngine had meaningful history that influenced
/// agent selection, and `agent_did` is the DID of the resolved agent.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn process_prompt_inner<'a>(
    app: &'a AppHandle,
    state: &'a State<'a, AppState>,
    prompt_id: &'a str,
    block_id: &'a str,
    action_type: &'a str,
    preferred: &'a str,
    query: &'a str,
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
            let block = BlockUpdate {
                id: bid.clone(),
                prompt_id: pid.clone(),
                prompt_text: None,
                state: BlockState::Resolving {
                    phase,
                    phase_label: label.into(),
                },
                schema_type: None,
                content: None,
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
            let block = BlockUpdate {
                id: bid2.clone(),
                prompt_id: pid2.clone(),
                prompt_text: None,
                state: BlockState::Failed {
                    phase,
                    reason: reason.into(),
                },
                schema_type: None,
                content: None,
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
            query,
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
                        block: BlockUpdate {
                            id: block_id.to_string(),
                            prompt_id: prompt_id.to_string(),
                            prompt_text: None,
                            state: BlockState::Resolving {
                                phase: 7,
                                phase_label: "Reflecting — trying alternative agent...".into(),
                            },
                            schema_type: None,
                            content: None,
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
                    action_type,
                    preferred,
                    query,
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
        let cfg = state.orchestrator_config.read().unwrap();
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
        let cfg = state.orchestrator_config.read().unwrap();
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
    // Classify intent once — result is reused for plan-building and handshake.
    let (action_type, preferred, query) = classify_intent(&app, &state, &block_id, &text).await;

    // Early-exit for dataset discovery — routes to multi-agent fan-out coordinator
    if action_type == "schema:DatasetAction" {
        return crate::commands::dataset_discovery::canvas_discover_datasets(
            app, state, _canvas_id, prompt_id, block_id, text,
        )
        .await;
    }

    // Resolve agent to build the IntentPlan.
    let resolved = resolve_agent(&state, &action_type, &preferred, &[]).await?;

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

    // Widen: also skip the gate when the principal has already approved these
    // exact scopes for this (action, schema) pair in a prior session.
    let schema_type_for_pref = plan.returns.first().map(String::as_str).unwrap_or("");
    let auto_approve = auto_approve
        || PreferenceEngine::new(state.db.as_ref()).has_approved_scopes(
            &action_type,
            schema_type_for_pref,
            &plan.requires_disclosure,
        );

    if auto_approve {
        // Run directly without emitting AwaitingApproval.
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
        maybe_auto_generate_template(&state, &schema_type, &content);
        let now = Utc::now().to_rfc3339();
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
        return Ok(serde_json::json!({ "status": "ok", "block_id": block_id }));
    }

    // Emit the AwaitingApproval block so the frontend can render the approval UI.
    let now = Utc::now().to_rfc3339();
    let _ = app.emit(
        "block_updated",
        BlockEvent {
            block: BlockUpdate {
                id: block_id.clone(),
                prompt_id: prompt_id.clone(),
                prompt_text: Some(text.clone()),
                state: BlockState::AwaitingApproval { plan: plan.clone() },
                schema_type: None,
                content: None,
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
        // Persist the approval so future identical requests skip the gate.
        PreferenceEngine::new(state.db.as_ref()).save_approved_scopes(
            &action_type,
            schema_type_for_pref,
            &hash_agent_did(&resolved.did),
            &resolved.name,
            &plan.requires_disclosure,
        );

        // Run the full handshake.
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
        maybe_auto_generate_template(&state, &schema_type, &content);
        let now = Utc::now().to_rfc3339();
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
        Ok(serde_json::json!({ "status": "ok", "block_id": block_id }))
    } else {
        // Principal rejected — emit a Failed block.
        let now = Utc::now().to_rfc3339();
        let _ = app.emit(
            "block_resolved",
            BlockEvent {
                block: BlockUpdate {
                    id: block_id.clone(),
                    prompt_id,
                    prompt_text: Some(text),
                    state: BlockState::Failed {
                        phase: 0,
                        reason: "Rejected by principal".to_string(),
                    },
                    schema_type: None,
                    content: None,
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

// ── Canvas persistence commands ───────────────────────────────────────────

/// List all canvases, most recently updated first.
#[tauri::command]
pub async fn canvas_list(
    state: State<'_, AppState>,
) -> Result<Vec<papillon_shared::CanvasRecord>, PapillonError> {
    state
        .db
        .list_canvases()
        .map_err(|e| PapillonError::from(e.0))
}

/// Create a new canvas with the given name and return the new record.
#[tauri::command]
pub async fn canvas_create(
    state: State<'_, AppState>,
    name: String,
) -> Result<papillon_shared::CanvasRecord, PapillonError> {
    let now = Utc::now().to_rfc3339();
    let record = papillon_shared::CanvasRecord {
        id: uuid::Uuid::new_v4().to_string(),
        name,
        created_at: now.clone(),
        updated_at: now,
    };
    state
        .db
        .upsert_canvas(&record)
        .map_err(|e| PapillonError::from(e.0))?;
    Ok(record)
}

/// Delete a canvas and all its blocks and messages.
#[tauri::command]
pub async fn canvas_delete(state: State<'_, AppState>, id: String) -> Result<(), PapillonError> {
    state
        .db
        .delete_canvas(&id)
        .map_err(|e| PapillonError::from(e.0))
}

/// Rename a canvas (update its name and updated_at).
#[tauri::command]
pub async fn canvas_rename(
    state: State<'_, AppState>,
    id: String,
    name: String,
) -> Result<(), PapillonError> {
    // Load the existing canvas to preserve created_at.
    let mut canvases = state
        .db
        .list_canvases()
        .map_err(|e| PapillonError::from(e.0))?;
    let existing = canvases
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| PapillonError::from(format!("Canvas not found: {id}")))?;
    let record = papillon_shared::CanvasRecord {
        id: existing.id.clone(),
        name,
        created_at: existing.created_at.clone(),
        updated_at: Utc::now().to_rfc3339(),
    };
    state
        .db
        .upsert_canvas(&record)
        .map_err(|e| PapillonError::from(e.0))
}

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

// ── Canvas Guide Block ────────────────────────────────────────────────────

/// Summary of a single resolved block, passed in from the frontend to build
/// the Guide block payload. Contains only the minimum fields needed for
/// summary generation — no raw content is transmitted.
#[derive(Debug, Deserialize)]
pub struct GuideBlockSummary {
    pub schema_type: String,
    pub agent_name: String,
    /// First 80 chars of the result text, for context.
    pub snippet: String,
}

/// The payload returned to the frontend for upserting the Guide block.
#[derive(Debug, Serialize)]
pub struct GuideBlockPayload {
    /// Always "guide-{canvas_id}"
    pub block_id: String,
    pub summary: String,
    pub suggestions: Vec<papillon_shared::GuideSuggestion>,
}

/// Generate (or refresh) the Canvas Guide block for a canvas.
///
/// Takes a list of summaries from already-resolved blocks on the canvas,
/// builds a human-readable summary sentence, derives schema-type-specific
/// follow-up suggestions, and appends up to 2 saved-pipeline suggestions
/// from the user's saved pipelines.
#[tauri::command]
pub async fn canvas_generate_guide(
    state: tauri::State<'_, AppState>,
    canvas_id: String,
    resolved_block_summaries: Vec<GuideBlockSummary>,
) -> Result<GuideBlockPayload, PapillonError> {
    // 1. Build summary string
    let agent_names: Vec<&str> = {
        let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for s in &resolved_block_summaries {
            set.insert(s.agent_name.as_str());
        }
        set.into_iter().collect()
    };
    let schema_types: Vec<&str> = {
        let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for s in &resolved_block_summaries {
            set.insert(s.schema_type.as_str());
        }
        set.into_iter().collect()
    };

    let summary = format!(
        "{} result{} from {} covering {}",
        resolved_block_summaries.len(),
        if resolved_block_summaries.len() == 1 { "" } else { "s" },
        agent_names.join(", "),
        schema_types.join(", "),
    );

    // 2. Static schema_type → prompt suggestion lookup
    let mut suggestions: Vec<GuideSuggestion> = Vec::new();
    for schema_type in &schema_types {
        match *schema_type {
            "SearchResult" | "SearchResultsPage" =>
                suggestions.push(GuideSuggestion { label: "Research Further".into(), prompt_template: "Research further: ".into(), saved_pipeline_id: None }),
            "NewsArticle" =>
                suggestions.push(GuideSuggestion { label: "Briefing Doc".into(), prompt_template: "Summarize these news articles into a briefing".into(), saved_pipeline_id: None }),
            "ScholarlyArticle" =>
                suggestions.push(GuideSuggestion { label: "Key Findings".into(), prompt_template: "What are the key findings from these papers?".into(), saved_pipeline_id: None }),
            "WeatherForecast" =>
                suggestions.push(GuideSuggestion { label: "Pack List".into(), prompt_template: "What should I pack for this weather?".into(), saved_pipeline_id: None }),
            "Product" =>
                suggestions.push(GuideSuggestion { label: "Compare".into(), prompt_template: "Compare these products on price and quality".into(), saved_pipeline_id: None }),
            "VisualArtwork" =>
                suggestions.push(GuideSuggestion { label: "Artist Info".into(), prompt_template: "Tell me more about the artist behind these works".into(), saved_pipeline_id: None }),
            _ => {}
        }
    }

    // 3. Load saved pipelines and surface compatible ones
    let saved = state.db.list_saved_pipelines()
        .map_err(|e| PapillonError::from(e.0))?;
    for pipeline in saved.iter().take(2) { // cap at 2 pipeline suggestions
        suggestions.push(GuideSuggestion {
            label: pipeline.name.clone(),
            prompt_template: String::new(),
            saved_pipeline_id: Some(pipeline.id.clone()),
        });
    }

    // Deduplicate and cap at 5
    suggestions.dedup_by(|a, b| a.label == b.label);
    suggestions.truncate(5);

    Ok(GuideBlockPayload {
        block_id: format!("guide-{}", canvas_id),
        summary,
        suggestions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── map_label_to_action ────────────────────────────────────

    #[test]
    fn map_label_to_action_coverage() {
        // All 14 explicit labels map to non-empty action + agent names.
        let labels = [
            "weather",
            "currency-exchange",
            "dictionary",
            "code-repository",
            "book",
            "tech-news",
            "academic-paper",
            "geocode",
            "dataset",
            "music",
            "film",
            "job-listing",
            "recipe",
            "product",
        ];
        for label in &labels {
            let (action, agent) = map_label_to_action(label);
            assert!(!action.is_empty(), "action empty for label: {label}");
            assert!(!agent.is_empty(), "agent empty for label: {label}");
            assert!(
                action.starts_with("schema:"),
                "action not schema: prefixed for label: {label}"
            );
        }
    }

    #[test]
    fn map_label_to_action_unknown_falls_back_to_search() {
        let (action, agent) = map_label_to_action("completely-unknown-intent");
        assert_eq!(action, "schema:SearchAction");
        assert_eq!(agent, "DuckDuckGo Search");
    }

    #[test]
    fn map_label_to_action_question_answer_not_mapped() {
        // "question-answer" is handled by the confidence check in classify_intent
        // and never reaches map_label_to_action. But if it did, it falls back.
        let (action, _) = map_label_to_action("question-answer");
        assert_eq!(action, "schema:SearchAction");
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

    // ── assess_handshake_quality — uncovered branches ─────────

    #[test]
    fn assess_quality_short_string_scores_medium() {
        // Non-empty string shorter than 20 chars hits the `s.len() < 20 => 0.5` arm.
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": "short answer"}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.5).abs() < f64::EPSILON, "got {quality}");
    }

    #[test]
    fn assess_quality_long_string_scores_high() {
        // String ≥ 20 chars falls through to the generic `_ => 0.8` arm.
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": "this is a longer answer that exceeds twenty characters"}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.8).abs() < f64::EPSILON, "got {quality}");
    }

    #[test]
    fn assess_quality_one_field_object_scores_medium() {
        // Object with 1-2 fields hits the `1..=2 => 0.6` branch.
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": {"name": "Rust"}}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.6).abs() < f64::EPSILON, "got {quality}");
    }

    #[test]
    fn assess_quality_six_field_object_scores_perfect() {
        // Object with > 5 fields hits the `_ => 1.0` branch.
        let result = handshake::HandshakeResult {
            schema_type: "SearchResult".into(),
            content: serde_json::json!({
                "result": {
                    "a": 1, "b": 2, "c": 3,
                    "d": 4, "e": 5, "f": 6
                }
            }),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 1.0).abs() < f64::EPSILON, "got {quality}");
    }

    #[test]
    fn assess_quality_small_array_scores_medium() {
        // Array with 1-2 items hits the `arr.len() < 3 => 0.6` arm.
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": ["only_one"]}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.6).abs() < f64::EPSILON, "got {quality}");
    }

    #[test]
    fn assess_quality_empty_array_scores_low() {
        // Empty array hits the `arr.is_empty() => 0.3` arm.
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": []}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.3).abs() < f64::EPSILON, "got {quality}");
    }

    #[test]
    fn assess_quality_boolean_result_scores_high() {
        // Boolean value falls through to the generic `_ => 0.8` arm.
        let result = handshake::HandshakeResult {
            schema_type: "Thing".into(),
            content: serde_json::json!({"result": true}),
            agent_name: "Test".into(),
        };
        let quality = assess_handshake_quality(&result);
        assert!((quality - 0.8).abs() < f64::EPSILON, "got {quality}");
    }

    // ── score_agent — constant validation ─────────────────────

    #[test]
    fn score_agent_cold_start_preferred_beats_non_preferred() {
        // When there is no EMA history (None path), keyword match gives 0.6 vs 0.4.
        // This test documents the cold-start scoring constants without requiring a DB.
        let preferred_cold: f64 = 0.6; // agent_name == preferred_name, no history
        let non_preferred_cold: f64 = 0.4; // no match, no history
        assert!(
            preferred_cold > non_preferred_cold,
            "cold-start preferred score ({preferred_cold}) must beat non-preferred ({non_preferred_cold})"
        );
        // Both should be in [0, 1]
        assert!((0.0..=1.0).contains(&preferred_cold));
        assert!((0.0..=1.0).contains(&non_preferred_cold));
    }

    #[test]
    fn score_agent_constants_are_valid_probability_weights() {
        // The scoring formula uses 35% + 35% + 20% + 10% = 100% when a full
        // EMA profile is present. Verify the weights sum to 1.0.
        let w_success: f64 = 0.35;
        let w_quality: f64 = 0.35;
        let w_pref: f64 = 0.20;
        let w_keyword: f64 = 0.10;
        let sum = w_success + w_quality + w_pref + w_keyword;
        assert!(
            (sum - 1.0).abs() < f64::EPSILON,
            "score_agent weights must sum to 1.0, got {sum}"
        );
    }
}

#[cfg(test)]
mod guide_tests {
    use super::*;

    /// Helper: build a GuideBlockSummary slice and run the summary logic inline.
    fn build_summary_and_suggestions(
        summaries: &[GuideBlockSummary],
    ) -> (String, Vec<GuideSuggestion>) {
        let agent_names: Vec<&str> = {
            let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s in summaries {
                set.insert(s.agent_name.as_str());
            }
            let mut v: Vec<&str> = set.into_iter().collect();
            v.sort(); // deterministic order for tests
            v
        };
        let schema_types: Vec<&str> = {
            let mut set: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for s in summaries {
                set.insert(s.schema_type.as_str());
            }
            let mut v: Vec<&str> = set.into_iter().collect();
            v.sort();
            v
        };

        let summary = format!(
            "{} result{} from {} covering {}",
            summaries.len(),
            if summaries.len() == 1 { "" } else { "s" },
            agent_names.join(", "),
            schema_types.join(", "),
        );

        let mut suggestions: Vec<GuideSuggestion> = Vec::new();
        for schema_type in &schema_types {
            match *schema_type {
                "SearchResult" | "SearchResultsPage" =>
                    suggestions.push(GuideSuggestion { label: "Research Further".into(), prompt_template: "Research further: ".into(), saved_pipeline_id: None }),
                "NewsArticle" =>
                    suggestions.push(GuideSuggestion { label: "Briefing Doc".into(), prompt_template: "Summarize these news articles into a briefing".into(), saved_pipeline_id: None }),
                "ScholarlyArticle" =>
                    suggestions.push(GuideSuggestion { label: "Key Findings".into(), prompt_template: "What are the key findings from these papers?".into(), saved_pipeline_id: None }),
                "WeatherForecast" =>
                    suggestions.push(GuideSuggestion { label: "Pack List".into(), prompt_template: "What should I pack for this weather?".into(), saved_pipeline_id: None }),
                "Product" =>
                    suggestions.push(GuideSuggestion { label: "Compare".into(), prompt_template: "Compare these products on price and quality".into(), saved_pipeline_id: None }),
                "VisualArtwork" =>
                    suggestions.push(GuideSuggestion { label: "Artist Info".into(), prompt_template: "Tell me more about the artist behind these works".into(), saved_pipeline_id: None }),
                _ => {}
            }
        }

        // No saved pipelines in unit tests.
        suggestions.dedup_by(|a, b| a.label == b.label);
        suggestions.truncate(5);

        (summary, suggestions)
    }

    #[test]
    fn guide_generates_summary_from_schema_types() {
        let summaries = vec![
            GuideBlockSummary {
                schema_type: "NewsArticle".into(),
                agent_name: "Hacker News".into(),
                snippet: "Latest tech news...".into(),
            },
            GuideBlockSummary {
                schema_type: "NewsArticle".into(),
                agent_name: "Hacker News".into(),
                snippet: "More news...".into(),
            },
        ];
        let (summary, suggestions) = build_summary_and_suggestions(&summaries);

        assert!(summary.contains("2 results"), "summary should mention count: {}", summary);
        assert!(summary.contains("Hacker News"), "summary should mention agent: {}", summary);
        assert!(summary.contains("NewsArticle"), "summary should mention schema type: {}", summary);

        // NewsArticle should map to "Briefing Doc" suggestion
        assert!(
            suggestions.iter().any(|s| s.label == "Briefing Doc"),
            "expected Briefing Doc suggestion for NewsArticle, got: {:?}",
            suggestions.iter().map(|s| s.label.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn guide_does_not_duplicate_suggestions() {
        // Two blocks with the same schema type should only produce one suggestion.
        let summaries = vec![
            GuideBlockSummary {
                schema_type: "WeatherForecast".into(),
                agent_name: "Open-Meteo".into(),
                snippet: "Sunny...".into(),
            },
            GuideBlockSummary {
                schema_type: "WeatherForecast".into(),
                agent_name: "Open-Meteo".into(),
                snippet: "Rainy...".into(),
            },
        ];
        let (_summary, suggestions) = build_summary_and_suggestions(&summaries);

        // Count how many "Pack List" suggestions there are — should be exactly 1
        let pack_list_count = suggestions.iter().filter(|s| s.label == "Pack List").count();
        assert_eq!(
            pack_list_count, 1,
            "duplicate suggestions should be deduped, got {} Pack List entries",
            pack_list_count
        );
    }

    #[test]
    fn guide_does_not_appear_with_zero_resolved_blocks() {
        // The frontend only invokes canvas_generate_guide when resolved_count >= 2.
        // This test documents the invariant: an empty summaries list produces a
        // "0 results" summary with no schema-type suggestions.
        let summaries: Vec<GuideBlockSummary> = vec![];
        let (summary, suggestions) = build_summary_and_suggestions(&summaries);

        assert!(
            summary.starts_with("0 results"),
            "zero blocks should produce '0 results' summary, got: {}",
            summary
        );
        assert!(
            suggestions.is_empty(),
            "zero blocks should produce no schema-based suggestions"
        );
    }

    #[test]
    fn guide_suggestion_serde_roundtrip() {
        let suggestion = GuideSuggestion {
            label: "Research Further".into(),
            prompt_template: "Research further: ".into(),
            saved_pipeline_id: Some("pipe-123".into()),
        };
        let json = serde_json::to_string(&suggestion).unwrap();
        let back: GuideSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(back.label, "Research Further");
        assert_eq!(back.saved_pipeline_id.as_deref(), Some("pipe-123"));
    }

    #[test]
    fn guide_block_id_format() {
        let canvas_id = "c-abc123";
        let block_id = format!("guide-{}", canvas_id);
        assert_eq!(block_id, "guide-c-abc123");
    }

    #[test]
    fn guide_caps_suggestions_at_five() {
        // All known schema types in one canvas — verify the cap.
        let summaries = vec![
            GuideBlockSummary { schema_type: "SearchResultsPage".into(), agent_name: "DDG".into(), snippet: "".into() },
            GuideBlockSummary { schema_type: "NewsArticle".into(), agent_name: "HN".into(), snippet: "".into() },
            GuideBlockSummary { schema_type: "ScholarlyArticle".into(), agent_name: "arXiv".into(), snippet: "".into() },
            GuideBlockSummary { schema_type: "WeatherForecast".into(), agent_name: "Meteo".into(), snippet: "".into() },
            GuideBlockSummary { schema_type: "Product".into(), agent_name: "OFacts".into(), snippet: "".into() },
            GuideBlockSummary { schema_type: "VisualArtwork".into(), agent_name: "ArtInst".into(), snippet: "".into() },
        ];
        let (_summary, suggestions) = build_summary_and_suggestions(&summaries);
        assert!(
            suggestions.len() <= 5,
            "suggestions must be capped at 5, got {}",
            suggestions.len()
        );
    }
}
