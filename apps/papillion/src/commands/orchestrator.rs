use tauri::State;

use crate::error::PapillionError;
use crate::state::AppState;
use papillion_shared::{OrchestratorConfig, OrchestratorStatus, ScenarioCard, SetupState};

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
