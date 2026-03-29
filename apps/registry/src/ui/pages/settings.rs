use leptos::prelude::*;

use crate::ui::api;

#[component]
pub fn SettingsPage() -> impl IntoView {
    let status = Resource::new(|| (), |_| api::get_status());

    view! {
        <div class="page">
            <div class="page-header">
                <h1 class="page-title">"Settings"</h1>
                <p class="page-subtitle">"Registry configuration and node identity."</p>
            </div>

            <div class="card" style="margin-bottom: var(--sp-xl)">
                <div class="card-header">
                    <span class="card-title">"Node Identity"</span>
                </div>
                <div class="card-body">
                    <Suspense fallback=|| view! { <div class="loading">"Loading…"</div> }>
                        {move || status.get().map(|result| match result {
                            Err(_) => view! {
                                <div class="empty-state">
                                    <div class="empty-state-title">"Unavailable"</div>
                                </div>
                            }.into_any(),
                            Ok(s) => view! {
                                <div>
                                    <div class="form-group">
                                        <label class="form-label">"DID"</label>
                                        <div class="identity-did">{s.did.clone()}</div>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">"TLS Certificate Fingerprint"</label>
                                        <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-2); background: var(--bg-2); padding: var(--sp-sm) var(--sp-md); border-radius: var(--r-md); word-break: break-all">
                                            {s.cert_fingerprint.clone()}
                                        </div>
                                        <div class="form-hint">
                                            "Share this fingerprint with peers so they can pin this node's TLS certificate."
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">"Public Endpoint"</label>
                                        <div style="font-family: var(--font-mono); font-size: 13px; color: var(--blue); background: var(--bg-2); padding: var(--sp-sm) var(--sp-md); border-radius: var(--r-md)">
                                            {s.endpoint.clone()}
                                        </div>
                                        <div class="form-hint">
                                            "Set via PAP_REGISTRY_ENDPOINT environment variable."
                                        </div>
                                    </div>
                                </div>
                            }.into_any(),
                        })}
                    </Suspense>
                </div>
            </div>

            <div class="card" style="margin-bottom: var(--sp-xl)">
                <div class="card-header">
                    <span class="card-title">"Environment Configuration"</span>
                </div>
                <div class="card-body">
                    <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                        "Configure the registry via environment variables:"
                    </p>
                    <EnvVar name="PAP_REGISTRY_PORT" default="7890" desc="HTTPS port to listen on" />
                    <EnvVar name="PAP_REGISTRY_HOST" default="0.0.0.0" desc="Host to bind to" />
                    <EnvVar name="PAP_REGISTRY_ENDPOINT" default="https://host:port" desc="Public URL advertised to peers" />
                    <EnvVar name="PAP_REGISTRY_ADMIN_TOKEN" default="(none — unrestricted)" desc="Bearer token for admin API routes" />
                </div>
            </div>

            <div class="card">
                <div class="card-header">
                    <span class="card-title">"Deployment"</span>
                </div>
                <div class="card-body">
                    <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                        "To deploy this registry:"
                    </p>
                    <ol style="font-size: 13px; color: var(--text-2); padding-left: var(--sp-lg); line-height: 2">
                        <li>"Build: " <code style="font-family: var(--font-mono); color: var(--purple); background: var(--purple-muted); padding: 2px 6px; border-radius: 4px">"cargo leptos build --release"</code></li>
                        <li>"Deploy binary + " <code style="font-family: var(--font-mono); color: var(--purple); background: var(--purple-muted); padding: 2px 6px; border-radius: 4px">"target/site/"</code> " to your server"</li>
                        <li>"Set " <code style="font-family: var(--font-mono); color: var(--gold); background: rgba(240,160,48,0.1); padding: 2px 6px; border-radius: 4px">"PAP_REGISTRY_ENDPOINT"</code> " to your public URL"</li>
                        <li>"Set " <code style="font-family: var(--font-mono); color: var(--gold); background: rgba(240,160,48,0.1); padding: 2px 6px; border-radius: 4px">"PAP_REGISTRY_ADMIN_TOKEN"</code> " for security"</li>
                    </ol>
                </div>
            </div>
        </div>
    }
}

#[component]
fn EnvVar(name: &'static str, default: &'static str, desc: &'static str) -> impl IntoView {
    view! {
        <div style="display:flex; gap: var(--sp-md); padding: var(--sp-xs) 0; border-bottom: 1px solid var(--border-subtle); align-items: baseline; flex-wrap: wrap">
            <code style="font-family: var(--font-mono); font-size: 12px; color: var(--purple); font-weight: 600; min-width: 260px">{name}</code>
            <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-3); min-width: 140px">{default}</span>
            <span style="font-size: 12px; color: var(--text-2)">{desc}</span>
        </div>
    }
}
