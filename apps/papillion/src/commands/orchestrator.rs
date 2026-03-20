use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use serde::Deserialize;
use tauri::State;

use crate::error::PapillionError;
use crate::state::{AppState, LOCAL_REGISTRY_URL};
use papillion_shared::{
    builtin_model_catalog, BuiltInModelInfo, ScenarioRunResult, ScenarioStepResult, LlmProvider,
    OrchestratorConfig, OrchestratorStatus, ReceiptInfo, ScenarioCard, SearchResult, SetupState,
};

/// Get the current orchestrator configuration.
#[tauri::command]
pub fn get_orchestrator_config(
    state: State<'_, AppState>,
) -> Result<OrchestratorConfig, PapillionError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    Ok(config.clone())
}

/// Save orchestrator configuration. When the provider is BuiltIn, this
/// automatically downloads (if needed) and loads the model so the
/// orchestrator transitions to Ready without a separate call.
#[tauri::command]
pub async fn configure_orchestrator(
    state: State<'_, AppState>,
    config: OrchestratorConfig,
) -> Result<OrchestratorConfig, PapillionError> {
    {
        let mut current = state
            .orchestrator_config
            .write()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        *current = config.clone();
    }

    // Auto-load the model when BuiltIn is selected
    if let LlmProvider::BuiltIn { ref model_id } = config.llm_provider {
        let mut mgr = state.model_manager.lock().await;
        mgr.ensure_loaded(model_id)
            .await
            .map_err(PapillionError::from)?;
    }

    Ok(config)
}

/// Get orchestrator status.
#[tauri::command]
pub async fn get_orchestrator_status(
    state: State<'_, AppState>,
) -> Result<OrchestratorStatus, PapillionError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?
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
pub fn get_setup_state(state: State<'_, AppState>) -> Result<SetupState, PapillionError> {
    let has_identity = state
        .signer
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?
        .is_some();
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    let llm_configured = config.llm_provider != LlmProvider::None;
    Ok(SetupState {
        identity_created: has_identity,
        llm_configured,
        setup_complete: has_identity,
    })
}

/// List available built-in models.
#[tauri::command]
pub fn list_builtin_models() -> Result<Vec<BuiltInModelInfo>, PapillionError> {
    Ok(builtin_model_catalog())
}

/// Download and load the configured built-in model. Call this after
/// configuring a BuiltIn provider to prime the model for inference.
#[tauri::command]
pub async fn load_builtin_model(
    state: State<'_, AppState>,
) -> Result<OrchestratorStatus, PapillionError> {
    let model_id = {
        let config = state
            .orchestrator_config
            .read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        match &config.llm_provider {
            LlmProvider::BuiltIn { model_id } => model_id.clone(),
            _ => return Err(PapillionError::from("Provider is not BuiltIn")),
        }
    };

    let mut mgr = state.model_manager.lock().await;
    mgr.ensure_loaded(&model_id)
        .await
        .map_err(PapillionError::from)?;

    Ok(OrchestratorStatus::Ready)
}

/// List scenario cards backed by real agents in the local registry.
#[tauri::command]
pub fn list_scenarios() -> Result<Vec<ScenarioCard>, PapillionError> {
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
            description:
                "On-device Mistral inference — your prompts never leave your machine".into(),
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
    Result { #[serde(rename = "Text")] text: String, #[serde(rename = "FirstURL")] first_url: String },
    Group { #[serde(rename = "Topics")] topics: Vec<DdgTopic>, #[serde(rename = "Name")] _name: String },
}

/// Public wrapper for the canvas module to reuse web search.
pub async fn web_search_public(query: &str) -> Result<Vec<SearchResult>, PapillionError> {
    web_search(query).await
}

/// Public wrapper for the canvas module to reuse Wikipedia lookup.
pub async fn wikipedia_search_public(query: &str) -> Result<Vec<SearchResult>, PapillionError> {
    wikipedia_search(query).await
}

/// Perform a real web search via DuckDuckGo Instant Answer JSON API.
async fn web_search(query: &str) -> Result<Vec<SearchResult>, PapillionError> {
    let client = reqwest::Client::builder()
        .user_agent("Papillion/0.1 (PAP Browser)")
        .build()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let resp: DdgResponse = client
        .get("https://api.duckduckgo.com/")
        .query(&[("q", query), ("format", "json"), ("no_html", "1"), ("skip_disambig", "1")])
        .send()
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?
        .json()
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

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
async fn wikipedia_search(query: &str) -> Result<Vec<SearchResult>, PapillionError> {
    let client = reqwest::Client::builder()
        .user_agent("Papillion/0.1 (PAP Browser; mailto:pap@baur-software.com)")
        .build()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let resp: WikiSearchResponse = client
        .get("https://en.wikipedia.org/w/rest.php/v1/search/page")
        .query(&[("q", query), ("limit", "5")])
        .send()
        .await
        .map_err(|e| PapillionError::from(format!("Wikipedia request: {e}")))?
        .json()
        .await
        .map_err(|e| PapillionError::from(format!("Wikipedia parse: {e}")))?;

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
) -> Result<ScenarioRunResult, PapillionError> {
    let now_str = || Utc::now().to_rfc3339();

    // Find the scenario
    let scenarios = list_scenarios()?;
    let scenario = scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .ok_or_else(|| PapillionError::from("Scenario not found"))?
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
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let registry = registries
            .get(LOCAL_REGISTRY_URL)
            .ok_or_else(|| PapillionError::from("Local registry not found"))?;
        let agent_ad = registry
            .all_advertisements()
            .iter()
            .find(|ad| ad.name == *agent_name)
            .ok_or_else(|| PapillionError::from("Agent not found in registry"))?
            .clone();
        let did = agent_ad.provider.did.clone();

        let seed_lock = state
            .principal_seed
            .read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let seed = seed_lock
            .as_ref()
            .ok_or_else(|| PapillionError::from("No identity configured"))?;
        let kp = PrincipalKeypair::from_bytes(seed)
            .map_err(|e| PapillionError::from(e.to_string()))?;
        (did, kp)
    };

    steps.push(ScenarioStepResult {
        step_number: 1,
        step_name: "Discover agent".into(),
        status: "completed".into(),
        detail: Some(format!("Found {} ({})", agent_name, &agent_did[..20])),
        timestamp: now_str(),
    });

    let principal_did = principal_kp.did();

    // ── Step 2: Issue mandate ───────────────────────────────
    let disclosure_set = if scenario.requires_disclosure.is_empty() {
        DisclosureSet::empty()
    } else {
        DisclosureSet::new(vec![DisclosureEntry::new(
            "schema:Person",
            scenario.requires_disclosure.clone(),
            vec![],
        )])
    };

    let scope = Scope::new(vec![ScopeAction::new(action)]);
    let ttl = Utc::now() + Duration::hours(1);

    let mut mandate = pap_core::mandate::Mandate::issue_root(
        principal_did.clone(),
        agent_did.clone(),
        scope,
        disclosure_set.clone(),
        ttl,
    );
    mandate.sign(principal_kp.signing_key());
    let mandate_hash = mandate.hash();

    steps.push(ScenarioStepResult {
        step_number: 2,
        step_name: "Issue mandate".into(),
        status: "completed".into(),
        detail: Some(format!("Mandate: {}...", &mandate_hash[..16])),
        timestamp: now_str(),
    });

    // ── Step 3: Open session ────────────────────────────────
    let mut token = CapabilityToken::mint(
        agent_did.clone(),
        action.clone(),
        principal_did.clone(),
        ttl,
    );
    token.sign(principal_kp.signing_key());

    let mut session = Session::initiate(&token, &agent_did, &principal_kp.verifying_key())
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let initiator_session_kp = SessionKeypair::generate();
    let receiver_session_kp = SessionKeypair::generate();

    session
        .open(initiator_session_kp.did(), receiver_session_kp.did())
        .map_err(|e| PapillionError::from(e.to_string()))?;

    steps.push(ScenarioStepResult {
        step_number: 3,
        step_name: "Open session".into(),
        status: "completed".into(),
        detail: Some(format!("Session: {}...", &session.id[..8])),
        timestamp: now_str(),
    });

    // ── Step 4: Exchange data ───────────────────────────────
    // Route to the actual backing service for each agent.
    let mut search_results: Option<Vec<SearchResult>> = None;
    let step4_detail = match scenario_id.as_str() {
        "search" => {
            if let Some(ref q) = query {
                match web_search(q).await {
                    Ok(results) => {
                        let count = results.len();
                        search_results = Some(results);
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
                            format!("Mistral: {}", truncated)
                        }
                        Err(e) => format!("On-device inference failed: {}", e),
                    }
                } else {
                    "On-device model not loaded \u{2014} configure BuiltIn provider in settings".into()
                }
            } else {
                "No query provided".into()
            }
        }
        _ => "Zero disclosure \u{2014} no personal data exchanged".into(),
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
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let property_refs = disclosure_set.property_refs();
    let mut receipt = TransactionReceipt::from_session(
        &session,
        property_refs.clone(),
        vec![format!("operator:{}_executed", action)],
        format!("{} executed", action),
        scenario.returns.join(", "),
    )
    .map_err(|e| PapillionError::from(e.to_string()))?;

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
        .map_err(|e| PapillionError::from(e.to_string()))?;

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
        success: true,
        error: None,
    };

    // Store in completed_runs for activity page
    if let Ok(mut runs) = state.completed_runs.write() {
        runs.push(result.clone());
    }

    Ok(result)
}

/// List completed scenario runs for the activity page.
#[tauri::command]
pub fn list_completed_runs(
    state: State<'_, AppState>,
) -> Result<Vec<ScenarioRunResult>, PapillionError> {
    let runs = state
        .completed_runs
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    Ok(runs.clone())
}
