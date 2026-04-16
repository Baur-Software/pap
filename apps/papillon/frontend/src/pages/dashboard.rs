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
        agents.get().iter().filter(|a| a.source == "compiled").count()
    };
    let total_count = move || agents.get().len();
    let active_agents = move || -> Vec<_> {
        agents.get().into_iter().filter(|a| a.source == "compiled").collect()
    };
    let catalog_agents = move || -> Vec<_> {
        agents.get().into_iter().filter(|a| a.source == "catalog").collect()
    };
    let catalog_count = move || {
        agents.get().iter().filter(|a| a.source == "catalog").count()
    };
    let catalog_open = RwSignal::new(false);

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
                                    each=active_agents
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

                    // ── Catalog agents (TOML-defined, collapsible) ──────────
                    <Show when=move || { catalog_count() > 0 }>
                        <div class="fleet-catalog-section">
                            <div
                                class="fleet-catalog-header"
                                on:click=move |_| catalog_open.update(|v| *v = !*v)
                            >
                                <span class="fleet-section-title">"CATALOG AGENTS"</span>
                                <span class="fleet-catalog-count">{move || catalog_count()}</span>
                                <span class="fleet-catalog-toggle">
                                    {move || if catalog_open.get() { "▲ COLLAPSE" } else { "▼ SHOW ALL" }}
                                </span>
                            </div>
                            <Show when=move || catalog_open.get()>
                                <div class="fleet-catalog-grid">
                                    <For
                                        each=catalog_agents
                                        key=|a| a.content_hash.clone()
                                        children=move |agent| {
                                            view! { <CatalogRow agent=agent /> }
                                        }
                                    />
                                </div>
                            </Show>
                        </div>
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

/// Compact single-row display for TOML catalog agents.
#[component]
fn CatalogRow(agent: AgentInfo) -> impl IntoView {
    let action = agent
        .capabilities
        .first()
        .map(|s| s.trim_start_matches("schema:").to_string())
        .unwrap_or_default();
    let live_class = if agent.live {
        "fleet-catalog-live"
    } else {
        "fleet-catalog-live offline"
    };

    view! {
        <div class="fleet-catalog-row">
            <span class={live_class} title=if agent.live { "handler registered" } else { "handler not loaded" }></span>
            <span class="fleet-catalog-name" title=agent.name.clone()>{agent.name.clone()}</span>
            <span class="fleet-catalog-action">{action}</span>
        </div>
    }
}

#[component]
fn AgentCard(agent: AgentInfo) -> impl IntoView {
    let short_did = agent.agent_did.as_deref().map(|d| {
        if d.len() > 20 {
            format!("{}...{}", &d[..10], &d[d.len()-6..])
        } else {
            d.to_string()
        }
    }).unwrap_or_else(|| "compiled".to_string());

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
