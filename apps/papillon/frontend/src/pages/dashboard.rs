use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::AgentInfo;

#[component]
pub fn DashboardPage() -> impl IntoView {
    let agents: RwSignal<Vec<AgentInfo>> = RwSignal::new(vec![]);
    let loading = RwSignal::new(true);

    Effect::new(move || {
        if bridge::tauri_available() {
            spawn_local(async move {
                loading.set(true);
                if let Ok(list) =
                    bridge::invoke_no_args::<Vec<AgentInfo>>("list_local_agents").await
                {
                    agents.set(list);
                }
                loading.set(false);
            });
        } else {
            loading.set(false);
        }
    });

    let active_count = move || {
        agents
            .get()
            .iter()
            .filter(|a| a.source == "compiled" || a.source == "catalog")
            .count()
    };
    let total_count = move || agents.get().len();

    view! {
        <div class="fleet-page">
            <div class="fleet-header">
                <div class="fleet-header-left">
                    <div class="fleet-header-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                            <rect x="2" y="2" width="20" height="20" rx="2"/>
                            <path d="M7 9h10M7 12h10M7 15h7"/>
                        </svg>
                    </div>
                    <div>
                        <div class="fleet-header-title">"AGENT FLEET & CHRYSALIS NODES"</div>
                        <div class="fleet-header-subtitle">"Multi-Agent Roster Management & Drop-in Coordination"</div>
                    </div>
                </div>
                <div class="fleet-header-right">
                    <span class="fleet-badge active">"● "{move || active_count()}" ACTIVE"</span>
                    <span class="fleet-badge total">"◎ "{move || total_count()}" TOTAL"</span>
                    <button class="fleet-add-btn">"+ ADD AGENT"</button>
                </div>
            </div>

            <div class="fleet-body">
                <div class="fleet-agents">
                    <div class="fleet-section-header">
                        <span class="fleet-section-check">"✓"</span>
                        <span class="fleet-section-title">"ACTIVE AGENTS"</span>
                        <span class="fleet-section-count">{move || format!("{} Online", active_count())}</span>
                        <span class="fleet-section-sort">"↕ SORT BY NAME"</span>
                    </div>

                    <Show
                        when=move || loading.get()
                        fallback=move || view! {
                            <div class="fleet-grid">
                                <For
                                    each=move || agents.get()
                                    key=|a| a.content_hash.clone()
                                    children=move |agent| {
                                        view! { <AgentCard agent=agent /> }
                                    }
                                />
                            </div>
                        }
                    >
                        <div class="fleet-loading">"Loading agents\u{2026}"</div>
                    </Show>
                </div>

                <div class="fleet-sidebar">
                    <div class="fleet-panel">
                        <div class="fleet-panel-header">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"/>
                                <path d="M12 8v4l3 3"/>
                            </svg>
                            "CHRYSALIS DROP-INS"
                        </div>
                        <div class="fleet-panel-body">
                            <div class="fleet-dropins-empty">
                                <p>"No remote Chrysalis nodes connected."</p>
                                <p>"Browse registries to discover federated agents."</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn AgentCard(agent: AgentInfo) -> impl IntoView {
    let short_did = agent
        .agent_did
        .as_deref()
        .map(|d| {
            if d.len() > 20 {
                format!("{}...{}", &d[..10], &d[d.len() - 6..])
            } else {
                d.to_string()
            }
        })
        .unwrap_or_else(|| "compiled".to_string());

    let action = agent.capabilities.first().cloned().unwrap_or_default();
    let action_label = action.trim_start_matches("schema:").to_string();

    let source_badge_class = match agent.source.as_str() {
        "catalog" => "agent-source-badge catalog",
        "user_created" => "agent-source-badge user",
        "generated" => "agent-source-badge generated",
        _ => "agent-source-badge compiled",
    };

    view! {
        <div class="agent-card">
            <div class="agent-card-header">
                <div class="agent-card-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">
                        <circle cx="12" cy="8" r="4"/>
                        <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                    </svg>
                </div>
                <div class="agent-card-info">
                    <div class="agent-card-name">{agent.name.clone()}</div>
                    <div class="agent-card-did">{short_did}</div>
                </div>
                <span class=source_badge_class>{agent.source.clone()}</span>
            </div>

            <div class="agent-card-stats">
                <div class="agent-stat">
                    <div class="agent-stat-label">"ROLE"</div>
                    <div class="agent-stat-value">{agent.provider_name.clone()}</div>
                </div>
                <div class="agent-stat">
                    <div class="agent-stat-label">"ACTION"</div>
                    <div class="agent-stat-value">{action_label}</div>
                </div>
            </div>

            <div class="agent-card-capabilities">
                <div class="agent-cap-label">"RETURNS"</div>
                <div class="agent-cap-tags">
                    <For
                        each=move || agent.returns.clone()
                        key=|r| r.clone()
                        children=|r| {
                            let label = r.trim_start_matches("schema:").to_string();
                            view! { <span class="agent-cap-tag">{label}</span> }
                        }
                    />
                </div>
            </div>
        </div>
    }
}
