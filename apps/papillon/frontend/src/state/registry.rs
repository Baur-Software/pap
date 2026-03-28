use leptos::prelude::*;
use papillon_shared::{AgentInfo, RegistryInfo};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;

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

impl RegistryState {
    /// Connect to a registry by URL — navigates, loads agents, updates signals.
    /// Used by the browse page auto-connect and the quickstart buttons.
    pub fn connect_to(&self, url: &str) {
        let url = url.to_string();
        self.current_url.set(url.clone());
        self.loading.set(true);
        self.error.set(None);

        let registry = *self;
        spawn_local(async move {
            #[derive(serde::Serialize)]
            struct NavArgs {
                url: String,
            }
            match bridge::invoke::<NavArgs, RegistryInfo>(
                "navigate_registry",
                &NavArgs { url: url.clone() },
            )
            .await
            {
                Ok(info) => {
                    registry.info.set(Some(info));
                    #[derive(serde::Serialize)]
                    struct ListArgs {
                        registry_url: String,
                    }
                    if let Ok(agents) = bridge::invoke::<ListArgs, Vec<AgentInfo>>(
                        "list_agents",
                        &ListArgs {
                            registry_url: url,
                        },
                    )
                    .await
                    {
                        registry.agents.set(agents);
                    }
                }
                Err(e) => registry.error.set(Some(e)),
            }
            registry.loading.set(false);
        });
    }
}
