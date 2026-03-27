use leptos::prelude::*;
use papillon_shared::{AgentInfo, RegistryInfo};

#[derive(Clone, Copy)]
pub struct RegistryState {
    pub current_url: RwSignal<String>,
    pub info: RwSignal<Option<RegistryInfo>>,
    pub agents: RwSignal<Vec<AgentInfo>>,
    pub selected_agent: RwSignal<Option<AgentInfo>>,
    pub action_filter: RwSignal<String>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<Option<String>>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            current_url: RwSignal::new(String::new()),
            info: RwSignal::new(None),
            agents: RwSignal::new(Vec::new()),
            selected_agent: RwSignal::new(None),
            action_filter: RwSignal::new(String::new()),
            loading: RwSignal::new(false),
            error: RwSignal::new(None),
        }
    }
}
