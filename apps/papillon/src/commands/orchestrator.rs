#![allow(clippy::unwrap_used)]
use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tauri::State;
use uuid::Uuid;

/// Compute SHA-256 hash of agent DID for profile indexing.
/// Never stores raw DID in memory DB.
pub(crate) fn hash_agent_did(agent_did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(agent_did.as_bytes());
    format!("{:x}", hasher.finalize())
}

use crate::db::{prelude::DatabaseOps, AgentProfile, Episode};
use crate::error::PapillonError;
use crate::state::{AppState, LOCAL_REGISTRY_URL};
use papillon_shared::{
    builtin_model_catalog, BuiltInModelInfo, LlmProvider, ModelAvailability, ModelDownloadProgress,
    OrchestratorConfig, OrchestratorStatus, PreferenceEngine, ReceiptInfo, ScenarioCard,
    ScenarioRunResult, ScenarioStepResult, SearchResult, SetupState,
};
use tauri::{AppHandle, Emitter};

/// Get the current orchestrator configuration.
#[tauri::command]
pub fn get_orchestrator_config(
    state: State<'_, AppState>,
) -> Result<OrchestratorConfig, PapillonError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    Ok(config.clone())
}

/// Save orchestrator configuration. When the provider is BuiltIn, this
/// automatically downloads (if needed) and loads the model so the
/// orchestrator transitions to Ready without a separate call.
#[tauri::command]
pub async fn configure_orchestrator(
    state: State<'_, AppState>,
    config: OrchestratorConfig,
) -> Result<OrchestratorConfig, PapillonError> {
    {
        let mut current = state
            .orchestrator_config
            .write()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        *current = config.clone();
    }

    // Persist the new config so it survives restarts.
    if let Ok(json) = serde_json::to_string(&config) {
        let _ = state.db.set_setting("orchestrator_config", &json);
    }

    // Load the model when BuiltIn is selected so that get_orchestrator_status
    // returns Ready immediately after this call returns.
    if let LlmProvider::BuiltIn { ref model_id } = config.llm_provider {
        let resource_dir = state
            .resource_dir
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?
            .clone();
        let data_dir = state
            .data_dir
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?
            .clone();
        let mut mgr = state.model_manager.lock().await;
        mgr.ensure_loaded(model_id, &resource_dir, &data_dir)
            .map_err(PapillonError::from)?;
    }

    Ok(config)
}

/// Get orchestrator status.
#[tauri::command]
pub async fn get_orchestrator_status(
    state: State<'_, AppState>,
) -> Result<OrchestratorStatus, PapillonError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();
    let status = match &config.llm_provider {
        LlmProvider::None => OrchestratorStatus::Disconnected,
        LlmProvider::BuiltIn { model_id } => {
            let mgr = state.model_manager.lock().await;
            if mgr.loaded.is_some() && mgr.model_id == *model_id {
                OrchestratorStatus::Ready
            } else {
                OrchestratorStatus::Disconnected
            }
        }
        LlmProvider::Mistral { .. }
        | LlmProvider::Ollama { .. }
        | LlmProvider::OpenAiCompatible { .. } => OrchestratorStatus::Ready,
    };
    Ok(status)
}

/// Check first-run setup state.
#[tauri::command]
pub fn get_setup_state(state: State<'_, AppState>) -> Result<SetupState, PapillonError> {
    let has_signer = state.signer.read().unwrap().is_some();
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?;
    let llm_configured = config.llm_provider != LlmProvider::None;
    Ok(SetupState {
        identity_created: has_signer,
        llm_configured,
        setup_complete: has_signer,
    })
}

/// List available built-in models.
#[tauri::command]
pub fn list_builtin_models() -> Result<Vec<BuiltInModelInfo>, PapillonError> {
    Ok(builtin_model_catalog())
}

/// Load the configured built-in model from bundled resources. Call this after
/// configuring a BuiltIn provider to prime the model for inference.
#[tauri::command]
pub async fn load_builtin_model(
    state: State<'_, AppState>,
) -> Result<OrchestratorStatus, PapillonError> {
    let model_id = {
        let config = state
            .orchestrator_config
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        match &config.llm_provider {
            LlmProvider::BuiltIn { model_id } => model_id.clone(),
            _ => return Err(PapillonError::from("Provider is not BuiltIn")),
        }
    };

    let resource_dir = state
        .resource_dir
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();
    let data_dir = state
        .data_dir
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();
    let mut mgr = state.model_manager.lock().await;
    mgr.ensure_loaded(&model_id, &resource_dir, &data_dir)
        .map_err(PapillonError::from)?;

    Ok(OrchestratorStatus::Ready)
}

/// Check whether each catalog model's files are present on disk.
#[tauri::command]
pub fn check_model_availability(
    state: State<'_, AppState>,
) -> Result<Vec<ModelAvailability>, PapillonError> {
    let resource_dir = state
        .resource_dir
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();
    let data_dir = state
        .data_dir
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();
    let catalog = builtin_model_catalog();
    Ok(catalog
        .iter()
        .map(|info| crate::inference::check_model_availability(&resource_dir, &data_dir, info))
        .collect())
}

/// Download a built-in model's GGUF weights and tokenizer from HuggingFace.
/// Emits `model_download_progress` events during the download.
#[tauri::command]
pub async fn download_builtin_model(
    app: AppHandle,
    state: State<'_, AppState>,
    model_id: String,
) -> Result<ModelAvailability, PapillonError> {
    let info = builtin_model_catalog()
        .into_iter()
        .find(|m| m.id == model_id)
        .ok_or_else(|| PapillonError::from(format!("Unknown model: {model_id}")))?;

    let data_dir = state
        .data_dir
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();
    let resource_dir = state
        .resource_dir
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();

    let models_dir = data_dir.join("models");
    std::fs::create_dir_all(&models_dir)
        .map_err(|e| PapillonError::from(format!("Create models dir: {e}")))?;

    // Download tokenizer first (small, ~500KB)
    let tokenizer_path = models_dir.join("tokenizer.json");
    if !tokenizer_path.exists() {
        let app_ref = app.clone();
        let mid: std::sync::Arc<str> = model_id.as_str().into();
        crate::inference::download_file(&info.tokenizer_url, &tokenizer_path, move |dl, total| {
            let pct = if total > 0 {
                std::cmp::min((dl * 100 / total) as u8, 100)
            } else {
                0
            };
            let _ = app_ref.emit(
                "model_download_progress",
                ModelDownloadProgress {
                    model_id: mid.to_string(),
                    file_type: "tokenizer".into(),
                    downloaded_bytes: dl,
                    total_bytes: total,
                    progress_pct: pct,
                },
            );
        })
        .await
        .map_err(PapillonError::from)?;
    }

    // Download GGUF weights (large, ~600MB+)
    let model_path = models_dir.join(&info.filename);
    if !model_path.exists() {
        let app_ref = app.clone();
        let mid: std::sync::Arc<str> = model_id.as_str().into();
        crate::inference::download_file(&info.download_url, &model_path, move |dl, total| {
            let pct = if total > 0 {
                std::cmp::min((dl * 100 / total) as u8, 100)
            } else {
                0
            };
            let _ = app_ref.emit(
                "model_download_progress",
                ModelDownloadProgress {
                    model_id: mid.to_string(),
                    file_type: "model".into(),
                    downloaded_bytes: dl,
                    total_bytes: total,
                    progress_pct: pct,
                },
            );
        })
        .await
        .map_err(PapillonError::from)?;
    }

    Ok(crate::inference::check_model_availability(
        &resource_dir,
        &data_dir,
        &info,
    ))
}

/// List scenario cards backed by real agents in the local registry.
#[tauri::command]
pub fn list_scenarios() -> Result<Vec<ScenarioCard>, PapillonError> {
    Ok(vec![
        ScenarioCard {
            id: "search".into(),
            title: "Web Search".into(),
            description: "Search the web via DuckDuckGo — zero disclosure, no tracking".into(),
            icon: "\u{1F50D}".into(),
            agent_name: "DuckDuckGo Search".into(),
            action_type: "schema:SearchAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:SearchResult".into()],
        },
        ScenarioCard {
            id: "knowledge".into(),
            title: "Wikipedia Lookup".into(),
            description: "Query Wikipedia's knowledge base — zero disclosure, public API".into(),
            icon: "\u{1F4DA}".into(),
            agent_name: "Wikipedia Knowledge".into(),
            action_type: "schema:SearchAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:Article".into()],
        },
        ScenarioCard {
            id: "ai".into(),
            title: "Ask AI".into(),
            description: "On-device inference — your prompts never leave your machine".into(),
            icon: "\u{1F9E0}".into(),
            agent_name: "On-Device AI".into(),
            action_type: "schema:AskAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:Answer".into()],
        },
    ])
}

// ── DuckDuckGo JSON API types ────────────────────────────────

#[derive(Deserialize)]
struct DdgResponse {
    #[serde(rename = "AbstractText")]
    abstract_text: String,
    #[serde(rename = "AbstractURL")]
    abstract_url: String,
    #[serde(rename = "AbstractSource")]
    abstract_source: String,
    #[serde(rename = "RelatedTopics")]
    related_topics: Vec<DdgTopic>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DdgTopic {
    Result {
        #[serde(rename = "Text")]
        text: String,
        #[serde(rename = "FirstURL")]
        first_url: String,
    },
    Group {
        #[serde(rename = "Topics")]
        topics: Vec<DdgTopic>,
        #[serde(rename = "Name")]
        _name: String,
    },
}

/// Public wrapper for the canvas module to reuse web search.
pub async fn web_search_public(query: &str) -> Result<Vec<SearchResult>, PapillonError> {
    web_search(query).await
}

/// Public wrapper for the canvas module to reuse Wikipedia lookup.
pub async fn wikipedia_search_public(query: &str) -> Result<Vec<SearchResult>, PapillonError> {
    wikipedia_search(query).await
}

/// Perform a real web search via DuckDuckGo Instant Answer JSON API.
async fn web_search(query: &str) -> Result<Vec<SearchResult>, PapillonError> {
    let client = reqwest::Client::builder()
        .user_agent("Papillon/0.1 (PAP Browser)")
        .build()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let resp: DdgResponse = client
        .get("https://api.duckduckgo.com/")
        .query(&[
            ("q", query),
            ("format", "json"),
            ("no_html", "1"),
            ("skip_disambig", "1"),
        ])
        .send()
        .await
        .map_err(|e| PapillonError::from(e.to_string()))?
        .json()
        .await
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let mut results = Vec::new();

    // Include the abstract if present
    if !resp.abstract_text.is_empty() {
        results.push(SearchResult {
            title: resp.abstract_source.clone(),
            url: resp.abstract_url.clone(),
            snippet: resp.abstract_text,
        });
    }

    // Flatten related topics
    fn collect_topics(topics: &[DdgTopic], out: &mut Vec<SearchResult>) {
        for topic in topics {
            match topic {
                DdgTopic::Result { text, first_url } => {
                    out.push(SearchResult {
                        title: text.chars().take(80).collect::<String>(),
                        url: first_url.clone(),
                        snippet: text.clone(),
                    });
                }
                DdgTopic::Group { topics, .. } => collect_topics(topics, out),
            }
            if out.len() >= 10 {
                return;
            }
        }
    }
    collect_topics(&resp.related_topics, &mut results);

    Ok(results)
}

// ── Wikipedia REST API types ─────────────────────────────────

#[derive(Deserialize)]
struct WikiSearchResponse {
    pages: Vec<WikiPage>,
}

#[derive(Deserialize)]
struct WikiPage {
    title: String,
    excerpt: Option<String>,
    description: Option<String>,
    key: String,
}

/// Query Wikipedia via the Wikimedia REST API (no auth, zero disclosure).
async fn wikipedia_search(query: &str) -> Result<Vec<SearchResult>, PapillonError> {
    let client = reqwest::Client::builder()
        .user_agent("Papillon/0.1 (PAP Browser; mailto:pap@baur-software.com)")
        .build()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let resp: WikiSearchResponse = client
        .get("https://en.wikipedia.org/w/rest.php/v1/search/page")
        .query(&[("q", query), ("limit", "5")])
        .send()
        .await
        .map_err(|e| PapillonError::from(format!("Wikipedia request: {e}")))?
        .json()
        .await
        .map_err(|e| PapillonError::from(format!("Wikipedia parse: {e}")))?;

    let results = resp
        .pages
        .into_iter()
        .map(|p| {
            let snippet = p
                .excerpt
                .or(p.description)
                .unwrap_or_default()
                // Strip HTML tags from excerpt
                .replace("<span class=\"searchmatch\">", "")
                .replace("</span>", "");
            SearchResult {
                title: p.title,
                url: format!("https://en.wikipedia.org/wiki/{}", p.key),
                snippet,
            }
        })
        .collect();

    Ok(results)
}

/// Run a scenario through the full 6-step PAP handshake.
#[tauri::command]
pub async fn run_scenario(
    state: State<'_, AppState>,
    scenario_id: String,
    query: Option<String>,
) -> Result<ScenarioRunResult, PapillonError> {
    let now_str = || Utc::now().to_rfc3339();
    let start_time = std::time::Instant::now();

    // Find the scenario
    let scenarios = list_scenarios()?;
    let scenario = scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .ok_or_else(|| PapillonError::from("Scenario not found"))?
        .clone();

    let agent_name = &scenario.agent_name;
    let action = &scenario.action_type;

    let mut steps = Vec::new();

    // ── Step 1: Discover agent ──────────────────────────────
    // Extract data from locks in a block so guards are dropped before any .await
    let (agent_did, principal_kp) = {
        let registries = state
            .registries
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        let registry = registries
            .get(LOCAL_REGISTRY_URL)
            .ok_or_else(|| PapillonError::from("Local registry not found"))?;
        let agent_ad = registry
            .all_advertisements()
            .iter()
            .find(|ad| ad.name == *agent_name)
            .ok_or_else(|| PapillonError::from("Agent not found in registry"))?
            .clone();
        let did = agent_ad.provider.did.clone();

        let seed_guard = state.principal_seed.read().unwrap();
        let seed = seed_guard
            .as_ref()
            .ok_or_else(|| PapillonError::from("No identity configured"))?;
        let kp = PrincipalKeypair::from_bytes(seed)
            .map_err(|e| PapillonError::from(format!("Failed to load keypair: {}", e)))?;
        (did, kp)
    };

    // ── Memory-informed agent selection ────────────────────
    // Consult the agent profile (if one exists) to calibrate the mandate.
    // This is advisory — missing profiles fall back to defaults.
    let agent_did_hash_for_profile = hash_agent_did(&agent_did);
    let agent_profile = state
        .db
        .get_agent_profile(&agent_did_hash_for_profile)
        .ok()
        .flatten();

    // Calibrate mandate TTL from historical avg_duration_ms.
    // Give 3x headroom over the observed average, clamped to [5 min, 4 hours].
    let ttl_hours = match &agent_profile {
        Some(p) if p.episode_count >= 3 => {
            let headroom_ms = p.avg_duration_ms * 3.0;
            (headroom_ms / 3_600_000.0).clamp(5.0 / 60.0, 4.0)
        }
        _ => 1.0, // default: 1 hour
    };

    let profile_detail = match &agent_profile {
        Some(p) => format!(
            " | profile: {:.0}% success, {:.0}ms avg, {} episodes",
            p.success_rate * 100.0,
            p.avg_duration_ms,
            p.episode_count,
        ),
        None => " | no prior history".to_string(),
    };

    steps.push(ScenarioStepResult {
        step_number: 1,
        step_name: "Discover agent".into(),
        status: "completed".into(),
        detail: Some(format!(
            "Found {} ({}){profile_detail}",
            agent_name,
            agent_did.get(..20).unwrap_or(&agent_did[..])
        )),
        timestamp: now_str(),
    });

    let principal_did = principal_kp.did();

    // ── Step 2: Issue mandate ───────────────────────────────
    let disclosure_set = if scenario.requires_disclosure.is_empty() {
        DisclosureSet::empty()
    } else {
        // Priority order for disclosure scope selection (most restrictive first):
        // 1. PreferenceEngine suggested scopes (intersection of principal-approved refs)
        // 2. Agent profile minimal_disclosure_refs (EMA-derived minimum across episodes)
        // 3. Scenario default requirements
        let schema_type_hint = scenario.returns.first().map(|s| s.as_str()).unwrap_or("");
        let pref_suggested = {
            let engine = PreferenceEngine::new(state.db.as_ref());
            engine.suggested_scopes(action, schema_type_hint)
        };

        let disclosure_props = if !pref_suggested.is_empty()
            && pref_suggested
                .iter()
                .all(|r| scenario.requires_disclosure.contains(r))
        {
            // Preference engine has approved scope data — use it
            pref_suggested
        } else {
            match &agent_profile {
                Some(p) if p.episode_count >= 5 => {
                    match serde_json::from_str::<Vec<String>>(&p.minimal_disclosure_refs) {
                        Ok(stored_refs)
                            if stored_refs
                                .iter()
                                .all(|r| scenario.requires_disclosure.contains(r)) =>
                        {
                            stored_refs
                        }
                        _ => scenario.requires_disclosure.clone(),
                    }
                }
                _ => scenario.requires_disclosure.clone(),
            }
        };

        DisclosureSet::new(vec![DisclosureEntry::new(
            "schema:Person",
            disclosure_props,
            vec![],
        )])
    };

    let scope = Scope::new(vec![ScopeAction::new(action)]);
    let ttl = Utc::now() + Duration::minutes((ttl_hours * 60.0) as i64);

    let mut mandate = pap_core::mandate::Mandate::issue_root(
        principal_did.clone(),
        agent_did.clone(),
        scope,
        disclosure_set.clone(),
        ttl,
    );
    mandate
        .sign(principal_kp.signing_key())
        .expect("Ed25519 is always supported");
    let mandate_hash = mandate.hash();

    steps.push(ScenarioStepResult {
        step_number: 2,
        step_name: "Issue mandate".into(),
        status: "completed".into(),
        detail: Some(format!(
            "Mandate: {}...",
            mandate_hash.get(..16).unwrap_or(&mandate_hash[..])
        )),
        timestamp: now_str(),
    });

    // ── Step 3: Open session ────────────────────────────────
    let mut token = CapabilityToken::mint(
        agent_did.clone(),
        action.clone(),
        principal_did.clone(),
        ttl,
    );
    token
        .sign(principal_kp.signing_key())
        .expect("Ed25519 is always supported");

    let mut session = Session::initiate(&token, &agent_did, &principal_kp.verifying_key())
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let initiator_session_kp = SessionKeypair::generate();
    let receiver_session_kp = SessionKeypair::generate();

    session
        .open(initiator_session_kp.did(), receiver_session_kp.did())
        .map_err(|e| PapillonError::from(e.to_string()))?;

    steps.push(ScenarioStepResult {
        step_number: 3,
        step_name: "Open session".into(),
        status: "completed".into(),
        detail: Some(format!(
            "Session: {}...",
            session.id.get(..8).unwrap_or(&session.id[..])
        )),
        timestamp: now_str(),
    });

    // ── Step 4: Exchange data ───────────────────────────────
    // Route to the actual backing service for each agent.
    // Track success: data exchange only succeeds if we get results or expected output.
    let mut search_results: Option<Vec<SearchResult>> = None;
    let mut data_exchange_success = false;
    let step4_detail = match scenario_id.as_str() {
        "search" => {
            if let Some(ref q) = query {
                match web_search(q).await {
                    Ok(results) => {
                        let count = results.len();
                        search_results = Some(results);
                        data_exchange_success = true;
                        format!("DuckDuckGo: \"{}\" \u{2014} {} results", q, count)
                    }
                    Err(e) => format!("DuckDuckGo search failed: {}", e),
                }
            } else {
                "No query provided".into()
            }
        }
        "knowledge" => {
            if let Some(ref q) = query {
                match wikipedia_search(q).await {
                    Ok(results) => {
                        let count = results.len();
                        search_results = Some(results);
                        data_exchange_success = true;
                        format!("Wikipedia: \"{}\" \u{2014} {} articles", q, count)
                    }
                    Err(e) => format!("Wikipedia lookup failed: {}", e),
                }
            } else {
                "No query provided".into()
            }
        }
        "ai" => {
            if let Some(ref q) = query {
                let mut mgr = state.model_manager.lock().await;
                if mgr.loaded.is_some() {
                    let prompt = format!("[INST] {} [/INST]", q);
                    match mgr.generate(&prompt, 200) {
                        Ok(response) => {
                            let truncated: String = response.chars().take(200).collect();
                            data_exchange_success = true;
                            format!("AI: {}", truncated)
                        }
                        Err(e) => format!("On-device inference failed: {}", e),
                    }
                } else {
                    "On-device model not loaded \u{2014} configure BuiltIn provider in settings"
                        .into()
                }
            } else {
                "No query provided".into()
            }
        }
        _ => {
            data_exchange_success = true;
            "Zero disclosure \u{2014} no personal data exchanged".into()
        }
    };
    steps.push(ScenarioStepResult {
        step_number: 4,
        step_name: "Exchange data".into(),
        status: "completed".into(),
        detail: Some(step4_detail),
        timestamp: now_str(),
    });

    // ── Step 5: Co-sign receipt ─────────────────────────────
    session
        .execute()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    let property_refs = disclosure_set.property_refs();
    let mut receipt = TransactionReceipt::from_session(
        &session,
        property_refs.clone(),
        vec![format!("operator:{}_executed", action)],
        format!("{} executed", action),
        scenario.returns.join(", "),
    )
    .map_err(|e| PapillonError::from(e.to_string()))?;

    receipt.co_sign(initiator_session_kp.signing_key());
    receipt.co_sign(receiver_session_kp.signing_key());

    let receipt_info = ReceiptInfo {
        session_id: receipt.session_id.clone(),
        action: receipt.action.clone(),
        initiator_did: receipt.initiating_agent_did.clone(),
        receiver_did: receipt.receiving_agent_did.clone(),
        property_refs,
        co_signed: receipt.signatures.len() == 2,
        timestamp: receipt.timestamp.to_rfc3339(),
    };

    steps.push(ScenarioStepResult {
        step_number: 5,
        step_name: "Co-sign receipt".into(),
        status: "completed".into(),
        detail: Some(format!("{} co-signatures", receipt.signatures.len())),
        timestamp: now_str(),
    });

    // ── Step 6: Close session ───────────────────────────────
    session
        .close()
        .map_err(|e| PapillonError::from(e.to_string()))?;

    steps.push(ScenarioStepResult {
        step_number: 6,
        step_name: "Close session".into(),
        status: "completed".into(),
        detail: Some("Session closed, ephemeral keys discarded".into()),
        timestamp: now_str(),
    });

    let receipt_url = format!("pap://local/receipts/{}", receipt_info.session_id);

    let result = ScenarioRunResult {
        scenario_id,
        agent_name: agent_name.clone(),
        steps,
        receipt: Some(receipt_info),
        receipt_url: Some(receipt_url),
        query,
        search_results,
        completed_at: now_str(),
        success: data_exchange_success,
        error: None,
    };

    // ── Record episode to SQLite ──────────────────────────────
    let duration_ms = start_time.elapsed().as_millis() as i64;

    // Hash the agent DID for indexing (never store raw DID in memory DB)
    let agent_did_hash = hash_agent_did(&agent_did);

    let receipt_session_id = result
        .receipt
        .as_ref()
        .map(|r| r.session_id.clone())
        .unwrap_or_default();

    let disclosure_refs = result
        .receipt
        .as_ref()
        .map(|r| serde_json::to_string(&r.property_refs).unwrap_or_else(|_| "[]".into()))
        .unwrap_or_else(|| "[]".into());

    // Store the full ScenarioRunResult as JSON-LD for later reconstruction
    let result_json = serde_json::to_string(&result).ok();

    let episode = Episode {
        id: Uuid::new_v4().to_string(),
        receipt_session_id,
        scenario_id: result.scenario_id.clone(),
        action_type: action.to_string(),
        agent_did_hash: agent_did_hash.clone(),
        agent_name: result.agent_name.clone(),
        outcome: if result.success {
            "success".into()
        } else {
            "failure".into()
        },
        outcome_detail: result.error.clone(),
        scope_exercised: serde_json::to_string(&[action.to_string()])
            .unwrap_or_else(|_| "[]".into()),
        disclosure_refs,
        duration_ms,
        decay_state: "Active".into(),
        intent_summary: result.query.clone(),
        result_json,
        query: result.query.clone(),
        recorded_at: Utc::now().to_rfc3339(),
    };

    // Write episode — non-blocking, memory is advisory
    if let Err(e) = state.db.insert_episode(&episode) {
        eprintln!("Failed to record episode: {e}");
    }

    // Update agent profile with exponential moving average
    update_agent_profile(&state, &agent_did_hash, &result.agent_name, &episode);

    Ok(result)
}

/// Compute quality metric from episode result completeness (0..1).
/// Quality measures how much useful data was returned and disclosure minimization:
/// - 0.0: failure or error
/// - 0.3–0.6: incomplete (no query provided, model not loaded, etc.)
/// - 0.7–0.9: partial results (some data but sparse)
/// - 1.0: complete results (rich data, full mandate scope used)
fn compute_quality(episode: &Episode) -> f64 {
    if episode.outcome != "success" {
        return 0.0;
    }

    // Try to extract result count or payload size from result_json or outcome_detail
    let detail = &episode.outcome_detail;
    if let Some(ref detail_str) = detail {
        // Look for patterns like "N results" or "N articles"
        if detail_str.contains("failed") {
            return 0.0;
        }
        if detail_str.contains("not loaded") {
            return 0.3;
        }
        if let Some(captures) = detail_str
            .split_whitespace()
            .find(|w| w.parse::<i32>().is_ok())
        {
            if let Ok(count) = captures.parse::<i32>() {
                // Map result count to quality: 0 → 0.3, 1-3 → 0.6, 4-9 → 0.85, 10+ → 1.0
                return match count {
                    0 => 0.3,
                    1..=3 => 0.6,
                    4..=9 => 0.85,
                    _ => 1.0,
                };
            }
        }
    }

    // If we have result_json, infer completeness from payload size/structure
    if let Some(ref json) = episode.result_json {
        let json_size = json.len();
        // Small (<100 bytes): minimal, quality 0.5
        // Medium (100-500): good, quality 0.8
        // Large (500+): rich, quality 1.0
        return match json_size {
            0..=100 => 0.5,
            101..=500 => 0.8,
            _ => 1.0,
        };
    }

    // No data to judge — conservative estimate
    0.5
}

/// Compute minimal disclosure refs as set intersection across all successful episodes.
/// Returns JSON array of property refs that were sufficient across all successes.
fn compute_minimal_disclosures(state: &State<'_, AppState>, agent_did_hash: &str) -> String {
    if let Ok(episodes) = state
        .db
        .list_episodes(None, Some(agent_did_hash), 1000, None)
    {
        let successful = episodes
            .iter()
            .filter(|ep| ep.outcome == "success")
            .collect::<Vec<_>>();

        if successful.is_empty() {
            return "[]".to_string();
        }

        // Parse disclosure refs from each episode
        let all_refs: Vec<Vec<String>> = successful
            .iter()
            .filter_map(|ep| serde_json::from_str(&ep.disclosure_refs).ok())
            .collect();

        if all_refs.is_empty() {
            return "[]".to_string();
        }

        // Compute intersection: refs that appear in ALL successful episodes
        if all_refs.is_empty() {
            return "[]".to_string();
        }

        let first = all_refs[0].clone();
        let intersection = all_refs[1..].iter().fold(first, |acc, cur| {
            acc.into_iter().filter(|r| cur.contains(r)).collect()
        });

        serde_json::to_string(&intersection).unwrap_or_else(|_| "[]".into())
    } else {
        "[]".to_string()
    }
}

/// Update agent profile with rolling EMA statistics.
fn update_agent_profile(
    state: &State<'_, AppState>,
    agent_did_hash: &str,
    agent_name: &str,
    episode: &Episode,
) {
    const ALPHA: f64 = 0.2; // EMA smoothing factor

    let existing = state.db.get_agent_profile(agent_did_hash).ok().flatten();
    let success = if episode.outcome == "success" {
        1.0
    } else {
        0.0
    };

    // Quality is based on result completeness, not success/failure binary
    let quality = compute_quality(episode);

    // Compute minimal disclosure set across all successful episodes
    let minimal_disclosure_refs = compute_minimal_disclosures(state, agent_did_hash);

    let profile = match existing {
        Some(prev) => AgentProfile {
            agent_did_hash: agent_did_hash.to_string(),
            agent_name: agent_name.to_string(),
            success_rate: ALPHA * success + (1.0 - ALPHA) * prev.success_rate,
            avg_quality: ALPHA * quality + (1.0 - ALPHA) * prev.avg_quality,
            avg_duration_ms: ALPHA * (episode.duration_ms as f64)
                + (1.0 - ALPHA) * prev.avg_duration_ms,
            episode_count: prev.episode_count + 1,
            minimal_disclosure_refs,
            last_used: episode.recorded_at.clone(),
            co_sign_refusals: prev.co_sign_refusals,
        },
        None => AgentProfile {
            agent_did_hash: agent_did_hash.to_string(),
            agent_name: agent_name.to_string(),
            success_rate: success,
            avg_quality: quality,
            avg_duration_ms: episode.duration_ms as f64,
            episode_count: 1,
            minimal_disclosure_refs,
            last_used: episode.recorded_at.clone(),
            co_sign_refusals: 0,
        },
    };

    if let Err(e) = state.db.upsert_agent_profile(&profile) {
        eprintln!("Failed to update agent profile: {e}");
    }
}

/// List completed scenario runs for the activity page.
/// Reads from the persistent SQLite episode store and reconstructs
/// ScenarioRunResult objects from stored JSON.
///
/// # Arguments
/// * `offset` - Number of records to skip (pagination start). Defaults to 0.
/// * `limit` - Maximum number of records to return. Defaults to 50, capped at 100.
#[tauri::command]
pub fn list_completed_runs(
    state: State<'_, AppState>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<Vec<ScenarioRunResult>, PapillonError> {
    let offset = offset.unwrap_or(0);
    let limit = std::cmp::min(limit.unwrap_or(50), 100) as usize;

    let episodes = state
        .db
        .list_episodes(None, None, limit, Some(offset as i64))?;
    let mut results = Vec::new();

    for ep in episodes {
        // Try to reconstruct from stored JSON first
        if let Some(ref json) = ep.result_json {
            if let Ok(run) = serde_json::from_str::<ScenarioRunResult>(json) {
                results.push(run);
                continue;
            }
        }
        // Fallback: build a minimal ScenarioRunResult from episode fields
        results.push(ScenarioRunResult {
            scenario_id: ep.scenario_id,
            agent_name: ep.agent_name,
            steps: vec![],
            receipt: None,
            receipt_url: None,
            query: ep.query,
            search_results: None,
            completed_at: ep.recorded_at,
            success: ep.outcome == "success",
            error: ep.outcome_detail,
        });
    }

    Ok(results)
}

/// List raw episodes for the Intent Partitions timeline.
///
/// Returns the full `Episode` records from the episode store so the frontend
/// can display decay state, scope, duration, and other partition metadata that
/// is not preserved in `ScenarioRunResult`.
#[tauri::command]
pub fn list_episodes(
    state: State<'_, AppState>,
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<Vec<Episode>, PapillonError> {
    let offset = offset.unwrap_or(0);
    let limit = std::cmp::min(limit.unwrap_or(50), 200) as usize;
    state
        .db
        .list_episodes(None, None, limit, Some(offset as i64))
        .map_err(|e| PapillonError::from(e.0))
}

/// List agent profiles for the frontend.
#[tauri::command]
pub fn list_agent_profiles(state: State<'_, AppState>) -> Result<Vec<AgentProfile>, PapillonError> {
    state
        .db
        .list_agent_profiles()
        .map_err(|e| PapillonError::from(e.0))
}
