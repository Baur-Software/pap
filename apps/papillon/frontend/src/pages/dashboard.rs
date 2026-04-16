use leptos::prelude::*;
use leptos::ev::MouseEvent;
use leptos_router::components::A;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use papillon_shared::{AgentInfo, RegistryInfo};

const LOCAL_URL: &str = "pap://local";

// ── Helper: shorten a DID for display ──────────────────────────────────────
fn short_did(did: &str) -> String {
    if did.len() > 26 {
        format!("{}…{}", &did[..14], &did[did.len() - 6..])
    } else {
        did.to_string()
    }
}

// ── Main page ───────────────────────────────────────────────────────────────

#[component]
pub fn DashboardPage() -> impl IntoView {
    // ── Network / node state ───────────────────────────────────────────────
    let node_did: RwSignal<String> = RwSignal::new(String::new());
    let node_port: RwSignal<u64> = RwSignal::new(0);
    let node_addresses: RwSignal<Vec<String>> = RwSignal::new(vec![]);
    let bookmarks: RwSignal<Vec<String>> = RwSignal::new(vec![]);
    let registry_infos: RwSignal<Vec<(String, RegistryInfo)>> = RwSignal::new(vec![]);

    // ── Connect form ───────────────────────────────────────────────────────
    let connect_input: RwSignal<String> = RwSignal::new(String::new());
    let connecting: RwSignal<bool> = RwSignal::new(false);
    let connect_error: RwSignal<Option<String>> = RwSignal::new(None);

    // ── Agents (secondary) ─────────────────────────────────────────────────
    let agents: RwSignal<Vec<AgentInfo>> = RwSignal::new(vec![]);
    let agents_loading: RwSignal<bool> = RwSignal::new(true);
    let agents_open: RwSignal<bool> = RwSignal::new(false);
    let catalog_open: RwSignal<bool> = RwSignal::new(false);

    // ── Load data on mount ─────────────────────────────────────────────────
    Effect::new(move || {
        if bridge::tauri_available() {
            spawn_local(async move {
                // 1. Node identity & counts
                if let Ok(info) =
                    bridge::invoke_no_args::<serde_json::Value>("get_node_info").await
                {
                    if let Some(d) = info.get("did").and_then(|v| v.as_str()) {
                        node_did.set(d.to_string());
                    }
                    if let Some(p) = info.get("port").and_then(|v| v.as_u64()) {
                        node_port.set(p);
                    }
                    let ac = info
                        .get("agent_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    let pc = info
                        .get("peer_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize;
                    registry_infos.update(|v| {
                        v.retain(|(u, _)| u != LOCAL_URL);
                        v.insert(
                            0,
                            (
                                LOCAL_URL.to_string(),
                                RegistryInfo {
                                    url: LOCAL_URL.to_string(),
                                    agent_count: ac,
                                    peer_count: pc,
                                },
                            ),
                        );
                    });
                }

                // 2. LAN addresses
                if let Ok(addrs) =
                    bridge::invoke_no_args::<Vec<String>>("get_node_addresses").await
                {
                    node_addresses.set(addrs);
                }

                // 3. Bookmarks
                if let Ok(bm) = bridge::invoke_no_args::<Vec<String>>("list_bookmarks").await {
                    let remote: Vec<String> = bm
                        .into_iter()
                        .filter(|u| u.as_str() != LOCAL_URL)
                        .collect();
                    bookmarks.set(remote);
                }

                // 4. Local agents (used in the collapsible section)
                agents_loading.set(true);
                if let Ok(list) =
                    bridge::invoke_no_args::<Vec<AgentInfo>>("list_local_agents").await
                {
                    agents.set(list);
                }
                agents_loading.set(false);
            });
        } else {
            agents_loading.set(false);
        }
    });

    // ── Derived: agent breakdown ───────────────────────────────────────────
    let active_agents = move || -> Vec<_> {
        agents
            .get()
            .into_iter()
            .filter(|a| a.source == "compiled")
            .collect()
    };
    let catalog_agents = move || -> Vec<_> {
        agents
            .get()
            .into_iter()
            .filter(|a| a.source == "catalog")
            .collect()
    };
    let active_count = move || {
        agents
            .get()
            .iter()
            .filter(|a| a.source == "compiled")
            .count()
    };
    let catalog_count = move || {
        agents
            .get()
            .iter()
            .filter(|a| a.source == "catalog")
            .count()
    };
    let total_count = move || agents.get().len();

    // ── Derived: local registry info ───────────────────────────────────────
    let local_info = move || {
        registry_infos
            .get()
            .into_iter()
            .find(|(u, _)| u == LOCAL_URL)
            .map(|(_, i)| i)
    };

    // ── Connect handler ────────────────────────────────────────────────────
    let do_connect = move |_: MouseEvent| {
        let url = connect_input.get();
        let url = url.trim().to_string();
        if url.is_empty() || connecting.get() {
            return;
        }
        connect_error.set(None);
        connecting.set(true);
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
                    registry_infos.update(|v| {
                        v.retain(|(u, _)| u != &url);
                        v.push((url.clone(), info));
                    });
                    #[derive(serde::Serialize)]
                    struct BmArgs {
                        registry_url: String,
                    }
                    let _ = bridge::invoke::<BmArgs, Vec<String>>(
                        "add_bookmark",
                        &BmArgs {
                            registry_url: url.clone(),
                        },
                    )
                    .await;
                    bookmarks.update(|b| {
                        if !b.contains(&url) {
                            b.push(url.clone());
                        }
                    });
                    connect_input.set(String::new());
                }
                Err(e) => {
                    connect_error.set(Some(e));
                }
            }
            connecting.set(false);
        });
    };

    // ── View ───────────────────────────────────────────────────────────────
    view! {
        <div class="chrysalis-page">

            // ── Header ──────────────────────────────────────────────────
            <div class="chrysalis-header">
                <div class="chrysalis-header-left">
                    <div class="chrysalis-header-icon">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="1.8">
                            <circle cx="12" cy="12" r="3"/>
                            <circle cx="12" cy="12" r="9"/>
                            <path d="M3.6 9h16.8M3.6 15h16.8"/>
                            <path d="M12 3c-2.5 3-4 5.5-4 9s1.5 6 4 9"/>
                            <path d="M12 3c2.5 3 4 5.5 4 9s-1.5 6-4 9"/>
                        </svg>
                    </div>
                    <div>
                        <div class="chrysalis-header-title">"CHRYSALIS NETWORK"</div>
                        <div class="chrysalis-header-subtitle">
                            "Federated Registry Discovery · " {move || {
                                let n = bookmarks.get().len();
                                if n == 0 {
                                    "No remote nodes connected".to_string()
                                } else if n == 1 {
                                    "1 remote node".to_string()
                                } else {
                                    format!("{n} remote nodes")
                                }
                            }}
                        </div>
                    </div>
                </div>
                <div class="chrysalis-header-right">
                    <Show when=move || { node_port.get() > 0 }>
                        <span class="chrysalis-node-address">
                            "◉ "
                            {move || {
                                let addrs = node_addresses.get();
                                if let Some(first) = addrs.first() {
                                    first.clone()
                                } else {
                                    format!("pap://localhost:{}", node_port.get())
                                }
                            }}
                        </span>
                    </Show>
                </div>
            </div>

            // ── Body ────────────────────────────────────────────────────
            <div class="chrysalis-body">

                // ── Left: Registry list ──────────────────────────────
                <div class="chrysalis-nodes">
                    <div class="chrysalis-section-label">"NETWORK NODES"</div>

                    // pap://local — always first
                    <div class="chrysalis-node-row local">
                        <div class="chrysalis-node-dot local" title="Built-in local node"></div>
                        <div class="chrysalis-node-info">
                            <span class="chrysalis-node-url">"pap://local"</span>
                            <span class="chrysalis-node-tag local">"LOCAL"</span>
                        </div>
                        <div class="chrysalis-node-meta">
                            {move || local_info().map(|i| {
                                format!("{} agents · {} peers", i.agent_count, i.peer_count)
                            }).unwrap_or_else(|| format!("{} agents", total_count()))}
                        </div>
                        <A href="/browse" attr:class="chrysalis-node-action">"BROWSE →"</A>
                    </div>

                    // Remote bookmarked nodes
                    <For
                        each=move || bookmarks.get()
                        key=|url| url.clone()
                        children=move |url| {
                            let url2 = url.clone();
                            let url3 = url.clone();
                            view! {
                                <div class="chrysalis-node-row remote">
                                    <div class="chrysalis-node-dot remote"
                                        title="Remote Chrysalis node">
                                    </div>
                                    <div class="chrysalis-node-info">
                                        <span class="chrysalis-node-url">{url.clone()}</span>
                                        <span class="chrysalis-node-tag remote">"REMOTE"</span>
                                    </div>
                                    <div class="chrysalis-node-meta">
                                        {move || {
                                            registry_infos.get()
                                                .into_iter()
                                                .find(|(u, _)| u == &url2)
                                                .map(|(_, i)| format!(
                                                    "{} agents · {} peers",
                                                    i.agent_count, i.peer_count
                                                ))
                                                .unwrap_or_else(|| "Not yet synced".to_string())
                                        }}
                                    </div>
                                    <A
                                        href=move || format!("/browse?url={}", url3.clone())
                                        attr:class="chrysalis-node-action"
                                    >
                                        "BROWSE →"
                                    </A>
                                </div>
                            }
                        }
                    />

                    // ── Connect form ──────────────────────────────────
                    <div class="chrysalis-connect">
                        <div class="chrysalis-connect-label">"CONNECT TO NODE"</div>
                        <div class="chrysalis-connect-row">
                            <input
                                type="text"
                                class="chrysalis-connect-input"
                                placeholder="pap://hostname or pap+http://hostname:7891"
                                prop:value=move || connect_input.get()
                                on:input=move |ev| {
                                    connect_input.set(
                                        leptos::prelude::event_target_value(&ev)
                                    );
                                }
                                on:keydown=move |ev| {
                                    use wasm_bindgen::JsCast;
                                    let ke: web_sys::KeyboardEvent =
                                        ev.unchecked_into();
                                    if ke.key() == "Enter" {
                                        do_connect(MouseEvent::new("click").unwrap());
                                    }
                                }
                            />
                            <button
                                class="chrysalis-connect-btn"
                                prop:disabled=move || connecting.get()
                                on:click=do_connect
                            >
                                {move || if connecting.get() { "CONNECTING…" } else { "CONNECT" }}
                            </button>
                        </div>
                        <Show when=move || connect_error.get().is_some()>
                            <div class="chrysalis-connect-error">
                                {move || connect_error.get().unwrap_or_default()}
                            </div>
                        </Show>
                    </div>
                </div>

                // ── Right: This-node identity panel ───────────────────
                <div class="chrysalis-identity">
                    <div class="chrysalis-panel">
                        <div class="chrysalis-panel-header">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none"
                                stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="3"/>
                                <circle cx="12" cy="12" r="9"/>
                                <path d="M3.6 9h16.8M3.6 15h16.8"/>
                                <path d="M12 3c-2.5 3-4 5.5-4 9s1.5 6 4 9"/>
                                <path d="M12 3c2.5 3 4 5.5 4 9s-1.5 6-4 9"/>
                            </svg>
                            "THIS NODE"
                        </div>
                        <div class="chrysalis-panel-body">
                            <Show
                                when=move || !node_did.get().is_empty()
                                fallback=move || view! {
                                    <div class="chrysalis-panel-empty">
                                        "Tauri bridge unavailable."
                                    </div>
                                }
                            >
                                <div class="chrysalis-identity-row">
                                    <div class="chrysalis-identity-label">"IDENTITY"</div>
                                    <div class="chrysalis-identity-value mono"
                                        title=move || node_did.get()>
                                        {move || short_did(&node_did.get())}
                                    </div>
                                </div>
                                <Show when=move || { node_port.get() > 0 }>
                                    <div class="chrysalis-identity-row">
                                        <div class="chrysalis-identity-label">"PORT"</div>
                                        <div class="chrysalis-identity-value mono">
                                            {move || node_port.get().to_string()}
                                        </div>
                                    </div>
                                </Show>
                                <Show when=move || !node_addresses.get().is_empty()>
                                    <div class="chrysalis-identity-row col">
                                        <div class="chrysalis-identity-label">"SHARE VIA"</div>
                                        <For
                                            each=move || node_addresses.get()
                                            key=|a| a.clone()
                                            children=|addr| view! {
                                                <div class="chrysalis-identity-addr mono">
                                                    {addr}
                                                </div>
                                            }
                                        />
                                    </div>
                                </Show>
                            </Show>
                        </div>
                    </div>
                </div>
            </div>

            // ── Agents section (collapsible, secondary) ──────────────
            <div class="chrysalis-agents">
                <div
                    class="chrysalis-agents-toggle"
                    on:click=move |_| agents_open.update(|v| *v = !*v)
                >
                    <span class="chrysalis-agents-title">
                        "AGENT ROSTER — pap://local"
                    </span>
                    <div class="chrysalis-agents-pills">
                        <span class="chrysalis-pill compiled">
                            {move || active_count().to_string()}
                            " compiled"
                        </span>
                        <span class="chrysalis-pill catalog">
                            {move || catalog_count().to_string()}
                            " catalog"
                        </span>
                    </div>
                    <span class="chrysalis-agents-caret">
                        {move || if agents_open.get() { "▲" } else { "▼" }}
                    </span>
                </div>

                <Show when=move || agents_open.get()>
                    <div class="chrysalis-agents-body">
                        <Show
                            when=move || agents_loading.get()
                            fallback=move || view! {
                                // Compiled agents
                                <Show when=move || { active_count() > 0 }>
                                    <div class="chrysalis-agents-group">"COMPILED"</div>
                                    <div class="fleet-grid">
                                        <For
                                            each=active_agents
                                            key=|a| a.content_hash.clone()
                                            children=move |agent| {
                                                view! { <AgentCard agent=agent /> }
                                            }
                                        />
                                    </div>
                                </Show>
                                // Catalog agents (nested collapse)
                                <Show when=move || { catalog_count() > 0 }>
                                    <div class="chrysalis-catalog-bar"
                                        on:click=move |_| {
                                            catalog_open.update(|v| *v = !*v)
                                        }
                                    >
                                        <span class="chrysalis-agents-group">"CATALOG"</span>
                                        <span class="chrysalis-pill catalog">
                                            {move || catalog_count().to_string()}
                                        </span>
                                        <span class="fleet-catalog-toggle">
                                            {move || if catalog_open.get() {
                                                "▲ COLLAPSE"
                                            } else {
                                                "▼ SHOW ALL"
                                            }}
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
                                </Show>
                            }
                        >
                            <div class="fleet-loading">"Loading agents\u{2026}"</div>
                        </Show>
                    </div>
                </Show>
            </div>
        </div>
    }
}

// ── Compact row for TOML catalog agents ────────────────────────────────────

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
            <span
                class={live_class}
                title=if agent.live { "handler registered" } else { "handler not loaded" }
            ></span>
            <span class="fleet-catalog-name" title=agent.name.clone()>
                {agent.name.clone()}
            </span>
            <span class="fleet-catalog-action">{action}</span>
        </div>
    }
}

// ── Agent card (compiled agents) ───────────────────────────────────────────

#[component]
fn AgentCard(agent: AgentInfo) -> impl IntoView {
    let short_did_val = agent
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
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                        stroke="currentColor" stroke-width="1.8">
                        <circle cx="12" cy="8" r="4"/>
                        <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                    </svg>
                </div>
                <div class="agent-card-info">
                    <div class="agent-card-name">{agent.name.clone()}</div>
                    <div class="agent-card-did">{short_did_val}</div>
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
