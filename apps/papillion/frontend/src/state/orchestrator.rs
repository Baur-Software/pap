use leptos::prelude::*;
use papillion_shared::{OrchestratorConfig, OrchestratorStatus, ScenarioCard, SetupState};

#[derive(Clone, Copy)]
pub struct OrchestratorState {
    pub config: RwSignal<OrchestratorConfig>,
    pub status: RwSignal<OrchestratorStatus>,
    pub scenarios: RwSignal<Vec<ScenarioCard>>,
    pub setup_state: RwSignal<Option<SetupState>>,
    pub selected_scenario: RwSignal<Option<ScenarioCard>>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<Option<String>>,
}

impl Default for OrchestratorState {
    fn default() -> Self {
        Self {
            config: RwSignal::new(OrchestratorConfig::default()),
            status: RwSignal::new(OrchestratorStatus::DemoOnly),
            scenarios: RwSignal::new(Vec::new()),
            setup_state: RwSignal::new(None),
            selected_scenario: RwSignal::new(None),
            loading: RwSignal::new(false),
            error: RwSignal::new(None),
        }
    }
}
