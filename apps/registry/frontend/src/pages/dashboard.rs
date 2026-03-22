use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::api::{self, RegistryStatus};

#[component]
pub fn DashboardPage() -> impl IntoView {
    let status = RwSignal::new(None::<RegistryStatus>);
    let error = RwSignal::new(None::<String>);
    let loading = RwSignal::new(true);

    Effect::new(move || {
        spawn_local(async move {
            match api::fetch_status().await {
                Ok(s) => {
                    status.set(Some(s));
                    error.set(None);
                }
                Err(e) => error.set(Some(e)),
            }
            loading.set(false);
        });
    });

    view! {
        <div class="page">
            <div class="page-header">
                <h1 class="page-title">"Dashboard"</h1>
                <p class="page-subtitle">"Federation node overview and registry health."</p>
            </div>

            {move || error.get().map(|e| view! {
                <div class="error-banner">"Failed to load status: " {e}</div>
            })}

            {move || if loading.get() {
                view! { <div class="loading"><span class="loading-dot">"Loading..."</span></div> }.into_any()
            } else if let Some(s) = status.get() {
                view! {
                    <div>
                        <div class="stat-grid">
                            <div class="stat-card">
                                <div class="stat-label">"Registered Agents"</div>
                                <div class="stat-value teal">{s.agent_count}</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">"Federation Peers"</div>
                                <div class="stat-value accent">{s.peer_count}</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-label">"Version"</div>
                                <div class="stat-value" style="font-size: 20px; font-family: var(--font-mono)">{s.version.clone()}</div>
                            </div>
                        </div>

                        <div class="identity-panel">
                            <div class="stat-label">"Node Identity"</div>
                            <div class="identity-did">{s.did.clone()}</div>
                            <div class="identity-fp">
                                <span style="color: var(--text-3)">"TLS fingerprint: "</span>
                                {s.cert_fingerprint.clone()}
                            </div>
                            <div style="margin-top: var(--sp-sm); font-size: 13px; color: var(--text-2)">
                                "Public endpoint: "
                                <span style="font-family: var(--font-mono); color: var(--blue)">{s.endpoint.clone()}</span>
                            </div>
                        </div>

                        <div class="card">
                            <div class="card-header">
                                <span class="card-title">"Federation Endpoints"</span>
                            </div>
                            <div class="card-body">
                                <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                                    "This node exposes the PAP federation protocol. Other registries can connect at:"
                                </p>
                                <EndpointRow method="GET"  path="/federation/identity" desc="Node identity and cert fingerprint" />
                                <EndpointRow method="GET"  path="/federation/query?action=..." desc="Query agents by Schema.org action" />
                                <EndpointRow method="POST" path="/federation/announce" desc="Receive agent advertisement" />
                                <EndpointRow method="GET"  path="/federation/peers" desc="Known peer list" />
                            </div>
                        </div>
                    </div>
                }.into_any()
            } else {
                view! { <div class="empty-state"><div class="empty-state-title">"No data"</div></div> }.into_any()
            }}
        </div>
    }
}

#[component]
fn EndpointRow(
    method: &'static str,
    path: &'static str,
    desc: &'static str,
) -> impl IntoView {
    let method_color = if method == "GET" { "var(--teal)" } else { "var(--gold)" };
    view! {
        <div style="display:flex; gap: var(--sp-md); align-items: baseline; padding: var(--sp-xs) 0; border-bottom: 1px solid var(--border-subtle)">
            <span style=format!("font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: {}; width: 36px; flex-shrink: 0", method_color)>
                {method}
            </span>
            <span style="font-family: var(--font-mono); font-size: 12px; color: var(--purple); flex: 1">
                {path}
            </span>
            <span style="font-size: 12px; color: var(--text-3)">{desc}</span>
        </div>
    }
}
