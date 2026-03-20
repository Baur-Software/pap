use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureEntry, DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{PrincipalKeypair, SessionKeypair};
use tauri::State;

use crate::error::PapillionError;
use crate::state::{AppState, DEMO_REGISTRY_URL};
use papillion_shared::{
    builtin_model_catalog, BuiltInModelInfo, DemoRunResult, DemoStepResult, LlmProvider,
    OrchestratorConfig, OrchestratorStatus, ReceiptInfo, ScenarioCard, SetupState,
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

/// Run a demo scenario through the full 6-step PAP handshake.
#[tauri::command]
pub fn run_demo_scenario(
    state: State<'_, AppState>,
    scenario_id: String,
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
    let agent_did = agent_ad.provider.did.clone();

    steps.push(DemoStepResult {
        step_number: 1,
        step_name: "Discover agent".into(),
        status: "completed".into(),
        detail: Some(format!("Found {} ({})", agent_name, &agent_did[..20])),
        timestamp: now_str(),
    });

    // Get principal signing key from stored seed
    let seed_lock = state
        .principal_seed
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?;
    let seed = seed_lock
        .as_ref()
        .ok_or_else(|| PapillionError::from("No identity configured"))?;
    let principal_kp = PrincipalKeypair::from_bytes(seed)
        .map_err(|e| PapillionError::from(e.to_string()))?;
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
    steps.push(DemoStepResult {
        step_number: 4,
        step_name: "Exchange data".into(),
        status: "completed".into(),
        detail: Some(if scenario.requires_disclosure.is_empty() {
            "Zero disclosure — no personal data exchanged".into()
        } else {
            format!(
                "Disclosed {} properties via PAP trust chain",
                scenario.requires_disclosure.len()
            )
        }),
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
