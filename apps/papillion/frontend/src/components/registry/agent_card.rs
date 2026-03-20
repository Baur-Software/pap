use leptos::prelude::*;
use papillion_shared::AgentInfo;

use crate::state::registry::RegistryState;

#[component]
pub fn AgentCard(agent: AgentInfo) -> impl IntoView {
    let registry = expect_context::<RegistryState>();
    let agent_for_click = agent.clone();
    let name = agent.name.clone();
    let provider = agent.provider_name.clone();
    let cap_count = agent.capabilities.len();
    let caps: Vec<String> = agent
        .capabilities
        .iter()
        .map(|c| c.trim_start_matches("schema:").to_string())
        .collect();
    let disclosure = if agent.requires_disclosure.is_empty() {
        None
    } else {
        Some(agent.requires_disclosure.join(", "))
    };

    let on_click = move |_| {
        registry.selected_agent.set(Some(agent_for_click.clone()));
    };

    view! {
        <div class="card" style="cursor: pointer;" on:click=on_click>
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                <h4 style="font-size: 14px; font-weight: 600;">{name}</h4>
                <span class="badge badge-accent">{cap_count}" cap"</span>
            </div>
            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">
                {provider}
            </div>
            <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                {caps.into_iter().map(|cap| view! {
                    <span class="badge badge-success">{cap}</span>
                }).collect::<Vec<_>>()}
            </div>
            {disclosure.map(|d| view! {
                <div style="margin-top: 8px; font-size: 11px; color: var(--warning);">
                    "Requires: "{d}
                </div>
            })}
        </div>
    }
}
