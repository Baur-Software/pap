use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::CapabilityToken;
#[cfg(any(test, feature = "demo"))]
use pap_core::session::Session;
use pap_did::{PrincipalKeypair, SessionKeypair};
#[cfg(any(test, feature = "demo"))]
use serde::Deserialize;
use tauri::State;

use crate::error::PapillionError;
use crate::state::AppState;
use papillion_shared::{
    builtin_model_catalog, BuiltInModelInfo, DemoRunResult, DemoStepResult, LlmProvider,
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
        LlmProvider::None => OrchestratorStatus::DemoOnly,
        LlmProvider::BuiltIn { model_id } => {
            let mgr = state.model_manager.lock().await;
            if mgr.loaded.is_some() && mgr.model_id == *model_id {
                OrchestratorStatus::Ready
            } else {
                OrchestratorStatus::Disconnected
            }
        }
        _ => OrchestratorStatus::Ready,
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

/// Returns true when the demo feature is compiled in and the demo registry is present.
fn has_demo_registry(state: &AppState) -> bool {
    #[cfg(any(test, feature = "demo"))]
    {
        state
            .registries
            .read()
            .map(|r| r.contains_key(crate::state::DEMO_REGISTRY_URL))
            .unwrap_or(false)
    }
    #[cfg(not(any(test, feature = "demo")))]
    {
        let _ = state;
        false
    }
}

/// Map a Schema.org action type to an icon.
fn icon_for_action(action: &str) -> &'static str {
    match action {
        "schema:SearchAction" => "\u{1F50D}",
        "schema:ReserveAction" => "\u{2708}\u{FE0F}",
        "schema:PayAction" => "\u{1F4B3}",
        "schema:AskAction" => "\u{1F9E0}",
        _ => "\u{1F916}",
    }
}

/// List scenario cards: demo cards + dynamically generated cards from all registries.
#[tauri::command]
pub fn list_scenarios(state: State<'_, AppState>) -> Result<Vec<ScenarioCard>, PapillionError> {
    let mut cards = Vec::new();

    // Include demo scenario cards when the demo registry is present
    if has_demo_registry(&state) {
        cards.extend(demo_scenario_cards());
    }

    // Generate cards from all connected registries (excluding demo)
    let registries = state
        .registries
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;

    for (url, registry) in registries.iter() {
        #[cfg(any(test, feature = "demo"))]
        if url == crate::state::DEMO_REGISTRY_URL {
            continue;
        }
        #[cfg(not(any(test, feature = "demo")))]
        let _ = url;

        for ad in registry.all_advertisements() {
            let primary_action = ad.capability.first().cloned().unwrap_or_default();
            let card = ScenarioCard {
                id: ad.hash(),
                title: ad.name.clone(),
                description: format!(
                    "{} by {}",
                    primary_action,
                    ad.provider.name
                ),
                icon: icon_for_action(&primary_action).into(),
                agent_name: ad.name.clone(),
                action_type: primary_action,
                requires_disclosure: ad.requires_disclosure.clone(),
                returns: ad.returns.clone(),
                agent_did: Some(ad.provider.did.clone()),
                endpoint: ad.endpoint.clone(),
            };
            cards.push(card);
        }
    }

    Ok(cards)
}

/// Hardcoded demo scenario cards.
fn demo_scenario_cards() -> Vec<ScenarioCard> {
    vec![
        ScenarioCard {
            id: "search".into(),
            title: "Web Search".into(),
            description: "Search the web with zero disclosure — no personal data leaves your device"
                .into(),
            icon: "\u{1F50D}".into(),
            agent_name: "Web Search Agent".into(),
            action_type: "schema:SearchAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:SearchResult".into()],
            agent_did: None,
            endpoint: None,
        },
        ScenarioCard {
            id: "flight".into(),
            title: "Book a Flight".into(),
            description:
                "Find and book flights with selective disclosure — only share name & nationality"
                    .into(),
            icon: "\u{2708}\u{FE0F}".into(),
            agent_name: "Flight Booking Agent".into(),
            action_type: "schema:ReserveAction".into(),
            requires_disclosure: vec![
                "schema:Person.name".into(),
                "schema:Person.nationality".into(),
            ],
            returns: vec!["schema:Ticket".into()],
            agent_did: None,
            endpoint: None,
        },
        ScenarioCard {
            id: "hotel".into(),
            title: "Book a Hotel".into(),
            description: "Reserve lodging with minimal disclosure — only your name required".into(),
            icon: "\u{1F3E8}".into(),
            agent_name: "Hotel Booking Agent".into(),
            action_type: "schema:ReserveAction".into(),
            requires_disclosure: vec!["schema:Person.name".into()],
            returns: vec!["schema:Reservation".into()],
            agent_did: None,
            endpoint: None,
        },
        ScenarioCard {
            id: "payment".into(),
            title: "Make a Payment".into(),
            description: "Process payments with ecash — zero disclosure, unlinkable transactions"
                .into(),
            icon: "\u{1F4B3}".into(),
            agent_name: "Payment Agent".into(),
            action_type: "schema:PayAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:Invoice".into()],
            agent_did: None,
            endpoint: None,
        },
        ScenarioCard {
            id: "ai".into(),
            title: "Ask AI".into(),
            description:
                "Get answers from a local AI — your prompts never leave your machine".into(),
            icon: "\u{1F9E0}".into(),
            agent_name: "Local AI Assistant".into(),
            action_type: "schema:AskAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:Answer".into()],
            agent_did: None,
            endpoint: None,
        },
    ]
}

// ── DuckDuckGo JSON API types (demo only) ─────────────────────

#[cfg(any(test, feature = "demo"))]
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

#[cfg(any(test, feature = "demo"))]
#[derive(Deserialize)]
#[serde(untagged)]
enum DdgTopic {
    Result { #[serde(rename = "Text")] text: String, #[serde(rename = "FirstURL")] first_url: String },
    Group { #[serde(rename = "Topics")] topics: Vec<DdgTopic>, #[serde(rename = "Name")] _name: String },
}

/// Perform a real web search via DuckDuckGo Instant Answer JSON API.
#[cfg(any(test, feature = "demo"))]
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

/// Run a demo scenario through the full 6-step PAP handshake.
#[tauri::command]
pub async fn run_demo_scenario(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    scenario_id: String,
    query: Option<String>,
) -> Result<DemoRunResult, PapillionError> {
    if !has_demo_registry(&state) {
        return Err(PapillionError::from("Demo registry not available"));
    }

    #[cfg(not(any(test, feature = "demo")))]
    {
        let _ = (app, scenario_id, query);
        return Err(PapillionError::from("Demo feature not compiled in"));
    }

    #[cfg(any(test, feature = "demo"))]
    {
        let result = run_demo_scenario_impl(&state, scenario_id, query).await?;
        persist_run(&app, &result);
        Ok(result)
    }
}

#[cfg(any(test, feature = "demo"))]
async fn run_demo_scenario_impl(
    state: &AppState,
    scenario_id: String,
    query: Option<String>,
) -> Result<DemoRunResult, PapillionError> {
    use crate::state::DEMO_REGISTRY_URL;

    let now_str = || Utc::now().to_rfc3339();

    // Find the scenario
    let scenarios = demo_scenario_cards();
    let scenario = scenarios
        .iter()
        .find(|s| s.id == scenario_id)
        .ok_or_else(|| PapillionError::from("Scenario not found"))?
        .clone();

    let agent_name = &scenario.agent_name;
    let action = &scenario.action_type;

    let mut steps = Vec::new();

    // ── Step 1: Discover agent ──────────────────────────────
    let (agent_did, principal_kp) = {
        let registries = state
            .registries
            .read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let registry = registries
            .get(DEMO_REGISTRY_URL)
            .ok_or_else(|| PapillionError::from("Demo registry not found"))?;
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

    steps.push(DemoStepResult {
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

    steps.push(DemoStepResult {
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

    steps.push(DemoStepResult {
        step_number: 3,
        step_name: "Open session".into(),
        status: "completed".into(),
        detail: Some(format!("Session: {}...", &session.id[..8])),
        timestamp: now_str(),
    });

    // ── Step 4: Exchange data ───────────────────────────────
    let mut search_results: Option<Vec<SearchResult>> = None;
    let step4_detail = if scenario_id == "search" {
        if let Some(ref q) = query {
            match web_search(q).await {
                Ok(results) => {
                    let count = results.len();
                    search_results = Some(results);
                    format!("Query: \"{}\" \u{2014} {} results via zero-disclosure session", q, count)
                }
                Err(e) => format!("Search failed: {}", e),
            }
        } else {
            "No query provided".into()
        }
    } else if scenario.requires_disclosure.is_empty() {
        "Zero disclosure \u{2014} no personal data exchanged".into()
    } else {
        format!(
            "Disclosed {} properties via PAP trust chain",
            scenario.requires_disclosure.len()
        )
    };
    steps.push(DemoStepResult {
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

    steps.push(DemoStepResult {
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

    steps.push(DemoStepResult {
        step_number: 6,
        step_name: "Close session".into(),
        status: "completed".into(),
        detail: Some("Session closed, ephemeral keys discarded".into()),
        timestamp: now_str(),
    });

    let receipt_url = format!("pap://demo/receipts/{}", receipt_info.session_id);

    let result = DemoRunResult {
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

/// Run a real agent session via HTTP using the 6-phase PAP handshake.
#[tauri::command]
pub async fn run_agent_session(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    agent_endpoint: String,
    agent_did: String,
    agent_name: String,
    action_type: String,
    disclosures: Vec<String>,
    query: Option<String>,
) -> Result<DemoRunResult, PapillionError> {
    use pap_proto::ProtocolMessage;
    use pap_transport::AgentClient;

    let now_str = || Utc::now().to_rfc3339();
    let mut steps = Vec::new();

    // ── Step 1: Discover agent (already known via registry) ──
    steps.push(DemoStepResult {
        step_number: 1,
        step_name: "Discover agent".into(),
        status: "completed".into(),
        detail: Some(format!("Agent: {} at {}", agent_name, agent_endpoint)),
        timestamp: now_str(),
    });

    // Get principal keypair from state
    let principal_kp = {
        let seed_lock = state
            .principal_seed
            .read()
            .map_err(|e| PapillionError::from(e.to_string()))?;
        let seed = seed_lock
            .as_ref()
            .ok_or_else(|| PapillionError::from("No identity configured"))?;
        PrincipalKeypair::from_bytes(seed)
            .map_err(|e| PapillionError::from(e.to_string()))?
    };
    let principal_did = principal_kp.did();

    // ── Step 2: Issue mandate ───────────────────────────────
    let disclosure_set = if disclosures.is_empty() {
        DisclosureSet::empty()
    } else {
        DisclosureSet::new(vec![DisclosureEntry::new(
            "schema:Person",
            disclosures.clone(),
            vec![],
        )])
    };

    let scope = Scope::new(vec![ScopeAction::new(&action_type)]);
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

    steps.push(DemoStepResult {
        step_number: 2,
        step_name: "Issue mandate".into(),
        status: "completed".into(),
        detail: Some(format!("Mandate: {}...", &mandate_hash[..16])),
        timestamp: now_str(),
    });

    // ── Step 3: Open session via HTTP ───────────────────────
    let mut token = CapabilityToken::mint(
        agent_did.clone(),
        action_type.clone(),
        principal_did.clone(),
        ttl,
    );
    token.sign(principal_kp.signing_key());

    let client = AgentClient::new(&agent_endpoint);

    // Phase 1: Present token
    let phase1_resp = client
        .present_token(token)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let (session_id, receiver_session_did) = match phase1_resp {
        ProtocolMessage::TokenAccepted {
            session_id,
            receiver_session_did,
        } => (session_id, receiver_session_did),
        ProtocolMessage::TokenRejected { reason } => {
            return Err(PapillionError::from(format!("Token rejected: {}", reason)));
        }
        ProtocolMessage::Error { code, message } => {
            return Err(PapillionError::from(format!(
                "Protocol error {}: {}",
                code, message
            )));
        }
        other => {
            return Err(PapillionError::from(format!(
                "Unexpected response: {}",
                other.message_type()
            )));
        }
    };

    // Phase 2: Exchange ephemeral DIDs
    let initiator_session_kp = SessionKeypair::generate();
    client
        .exchange_did(&session_id, initiator_session_kp.did())
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let session_id_prefix = if session_id.len() >= 8 {
        &session_id[..8]
    } else {
        &session_id
    };
    steps.push(DemoStepResult {
        step_number: 3,
        step_name: "Open session".into(),
        status: "completed".into(),
        detail: Some(format!("Session: {}...", session_id_prefix)),
        timestamp: now_str(),
    });

    // ── Step 4: Exchange data via HTTP ──────────────────────
    // Phase 3: Send disclosures
    let disclosure_values: Vec<serde_json::Value> = disclosures
        .iter()
        .map(|d| serde_json::json!({ "property": d, "value": "[disclosed]" }))
        .collect();
    client
        .send_disclosures(&session_id, disclosure_values)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    // Phase 4: Request execution
    let exec_resp = client
        .request_execution(&session_id)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let exec_result = match exec_resp {
        ProtocolMessage::ExecutionResult { result } => result,
        ProtocolMessage::Error { code, message } => {
            return Err(PapillionError::from(format!(
                "Execution error {}: {}",
                code, message
            )));
        }
        other => {
            return Err(PapillionError::from(format!(
                "Unexpected execution response: {}",
                other.message_type()
            )));
        }
    };

    let step4_detail = if disclosures.is_empty() {
        "Zero disclosure \u{2014} no personal data exchanged".into()
    } else {
        format!(
            "Disclosed {} properties via PAP trust chain",
            disclosures.len()
        )
    };

    // Parse search results if the execution result contains them
    let search_results: Option<Vec<SearchResult>> = exec_result
        .get("search_results")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    steps.push(DemoStepResult {
        step_number: 4,
        step_name: "Exchange data".into(),
        status: "completed".into(),
        detail: Some(step4_detail),
        timestamp: now_str(),
    });

    // ── Step 5: Co-sign receipt via HTTP ─────────────────────
    let property_refs = disclosure_set.property_refs();

    // Build the receipt directly (we drove the session via HTTP, not locally)
    let mut receipt = TransactionReceipt {
        session_id: session_id.clone(),
        action: action_type.clone(),
        initiating_agent_did: initiator_session_kp.did(),
        receiving_agent_did: receiver_session_did,
        disclosed_by_initiator: property_refs.clone(),
        disclosed_by_receiver: vec![format!("operator:{}_executed", action_type)],
        executed: format!("{} executed", action_type),
        returned: exec_result.to_string(),
        timestamp: Utc::now(),
        signatures: vec![],
    };

    // Initiator signs first
    receipt.co_sign(initiator_session_kp.signing_key());

    // Phase 5: Send receipt for co-signing
    let receipt_resp = client
        .exchange_receipt(&session_id, receipt.clone())
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    let co_signed_receipt = match receipt_resp {
        ProtocolMessage::ReceiptCoSigned {
            receipt: co_signed,
        } => co_signed,
        _ => receipt, // Fall back to our half-signed receipt
    };

    let receipt_info = ReceiptInfo {
        session_id: co_signed_receipt.session_id.clone(),
        action: co_signed_receipt.action.clone(),
        initiator_did: co_signed_receipt.initiating_agent_did.clone(),
        receiver_did: co_signed_receipt.receiving_agent_did.clone(),
        property_refs,
        co_signed: co_signed_receipt.signatures.len() >= 2,
        timestamp: co_signed_receipt.timestamp.to_rfc3339(),
    };

    steps.push(DemoStepResult {
        step_number: 5,
        step_name: "Co-sign receipt".into(),
        status: "completed".into(),
        detail: Some(format!(
            "{} co-signatures",
            co_signed_receipt.signatures.len()
        )),
        timestamp: now_str(),
    });

    // ── Step 6: Close session via HTTP ──────────────────────
    client
        .close_session(&session_id)
        .await
        .map_err(|e| PapillionError::from(e.to_string()))?;

    steps.push(DemoStepResult {
        step_number: 6,
        step_name: "Close session".into(),
        status: "completed".into(),
        detail: Some("Session closed, ephemeral keys discarded".into()),
        timestamp: now_str(),
    });

    let receipt_url = format!(
        "{}/receipts/{}",
        agent_endpoint.trim_end_matches('/'),
        receipt_info.session_id
    );

    let result = DemoRunResult {
        scenario_id: format!("real-{}", action_type),
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

    persist_run(&app, &result);

    Ok(result)
}

/// Persist a run result to the sessions store.
fn persist_run(app: &tauri::AppHandle, result: &DemoRunResult) {
    use tauri_plugin_store::StoreExt;
    if let Ok(store) = app.store("sessions.json") {
        let existing: Vec<DemoRunResult> = store
            .get("completed_runs")
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let mut all = existing;
        all.push(result.clone());
        store.set("completed_runs", serde_json::to_value(&all).unwrap_or_default());
    }
}

/// Load persisted runs from the sessions store into AppState.
pub fn load_persisted_runs(app: &tauri::AppHandle) {
    use tauri::Manager;
    use tauri_plugin_store::StoreExt;
    if let Ok(store) = app.store("sessions.json") {
        if let Some(runs) = store
            .get("completed_runs")
            .and_then(|v| serde_json::from_value::<Vec<DemoRunResult>>(v).ok())
        {
            let state = app.state::<AppState>();
            let mut current = match state.completed_runs.write() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            *current = runs;
        }
    }
}

/// List completed demo runs for the activity page.
#[tauri::command]
pub fn list_completed_runs(
    state: State<'_, AppState>,
) -> Result<Vec<DemoRunResult>, PapillionError> {
    let runs = state
        .completed_runs
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    Ok(runs.clone())
}
