use leptos::prelude::*;
use papillon_shared::{AgentInfo, AgentLifecycle};

use crate::state::registry::RegistryState;

#[component]
pub fn AgentSidebar(agents: ReadSignal<Vec<AgentInfo>>) -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    let published = move || {
        agents
            .get()
            .into_iter()
            .filter(|a| a.lifecycle == AgentLifecycle::Published)
            .collect::<Vec<_>>()
    };
    let drafts = move || {
        agents
            .get()
            .into_iter()
            .filter(|a| a.lifecycle == AgentLifecycle::Draft)
            .collect::<Vec<_>>()
    };
    let unpublished = move || {
        agents
            .get()
            .into_iter()
            .filter(|a| a.lifecycle == AgentLifecycle::Unpublished)
            .collect::<Vec<_>>()
    };

    let on_new = move |_| {
        registry.active_agent_id.set(Some("__new__".to_string()));
    };

    view! {
        <div style="width: 240px; background: var(--bg-secondary); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; height: 100%;">
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border);">
                <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-secondary);">"Agents"</span>
                <button
                    style="font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 5px; background: rgba(108,92,231,0.15); color: #a78bfa; border: 1px solid rgba(108,92,231,0.25); cursor: pointer;"
                    on:click=on_new
                >
                    "+ New"
                </button>
            </div>
            <div style="overflow-y: auto; flex: 1; padding: 4px 0;">
                <AgentGroup label="Published" agents=Signal::derive(move || published()) />
                <AgentGroup label="Draft" agents=Signal::derive(move || drafts()) />
                <AgentGroup label="Unpublished" agents=Signal::derive(move || unpublished()) />
            </div>
        </div>
    }
}

#[component]
fn AgentGroup(label: &'static str, agents: Signal<Vec<AgentInfo>>) -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    move || {
        let items = agents.get();
        if items.is_empty() {
            return view! { <div></div> }.into_any();
        }
        view! {
            <div>
                <div style="padding: 8px 14px 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-tertiary);">
                    {label}
                </div>
                {items.into_iter().map(|agent| {
                    let name = agent.name.clone();
                    let verb = papillon_shared::schema_phrase(
                        agent.capabilities.first().map(|s| s.as_str()).unwrap_or("")
                    );
                    let agent_name_for_click = agent.name.clone();
                    let is_active = {
                        let n = agent_name_for_click.clone();
                        move || registry.active_agent_id.get().as_deref() == Some(&n)
                    };
                    let dot_color = match agent.lifecycle {
                        AgentLifecycle::Published => "#6c5ce7",
                        AgentLifecycle::Draft => "#64748b",
                        AgentLifecycle::Unpublished => "#ef4444",
                    };
                    view! {
                        <div
                            style=move || format!(
                                "display: flex; align-items: center; gap: 8px; padding: 7px 14px; cursor: pointer; border-left: 2px solid {}; background: {};",
                                if is_active() { "#6c5ce7" } else { "transparent" },
                                if is_active() { "rgba(108,92,231,0.08)" } else { "transparent" }
                            )
                            on:click=move |_| {
                                registry.active_agent_id.set(Some(agent_name_for_click.clone()));
                            }
                        >
                            <div style=format!("width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; background: {dot_color};")></div>
                            <div style="flex: 1; min-width: 0;">
                                <div style="font-size: 12px; color: #cbd5e1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{name}</div>
                                <div style="font-size: 10px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">{verb}</div>
                            </div>
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </div>
        }.into_any()
    }
}
