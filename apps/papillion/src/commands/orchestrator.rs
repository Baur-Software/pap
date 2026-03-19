use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use serde::Deserialize;
use tauri::State;

use crate::error::PapillionError;
use crate::state::{AppState, DEMO_REGISTRY_URL};
use papillion_shared::{
    DemoRunResult, DemoStepResult, OrchestratorConfig, OrchestratorStatus, ReceiptInfo,
    ScenarioCard, SearchResult, SetupState,
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

/// Save orchestrator configuration.
#[tauri::command]
pub fn configure_orchestrator(
    state: State<'_, AppState>,
    config: OrchestratorConfig,
) -> Result<OrchestratorConfig, PapillionError> {
    let mut current = state
        .orchestrator_config
        .write()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    *current = config.clone();
    Ok(config)
}

/// Get orchestrator status.
#[tauri::command]
pub fn get_orchestrator_status(
    state: State<'_, AppState>,
) -> Result<OrchestratorStatus, PapillionError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    let status = match &config.llm_provider {
        papillion_shared::LlmProvider::None => OrchestratorStatus::DemoOnly,
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
    let llm_configured = config.llm_provider != papillion_shared::LlmProvider::None;
    Ok(SetupState {
        identity_created: has_identity,
        llm_configured,
        setup_complete: has_identity,
    })
}

/// List demo scenario cards for the Home page.
#[tauri::command]
pub fn list_scenarios() -> Result<Vec<ScenarioCard>, PapillionError> {
    Ok(vec![
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

/// Run a demo scenario through the full 6-step PAP handshake.
#[tauri::command]
pub async fn run_demo_scenario(
    state: State<'_, AppState>,
    scenario_id: String,
    query: Option<String>,
) -> Result<DemoRunResult, PapillionError> {
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
