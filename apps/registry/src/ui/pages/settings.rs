use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::ui::api;
use crate::ui::api::{get_cors_origins, update_cors_origins};

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
                    <span class="card-title">"Authentication Status"</span>
                </div>
                <div class="card-body">
                    <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                        "Authentication and API key configuration status."
                    </p>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: var(--sp-lg)">
                        <div style="padding: var(--sp-md); background: var(--bg-2); border-radius: var(--r-md); border: 1px solid var(--border-subtle)">
                            <div style="font-size: 12px; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; margin-bottom: var(--sp-sm)">"Bearer Token"</div>
                            <div style="font-size: 14px; color: var(--text-1)">
                                "Set via "
                                <code style="font-family: var(--font-mono); color: var(--gold); background: rgba(240,160,48,0.1); padding: 2px 4px; border-radius: 3px">
                                    "PAP_REGISTRY_ADMIN_TOKEN"
                                </code>
                            </div>
                            <div style="font-size: 12px; color: var(--text-3); margin-top: var(--sp-sm)">"Required for admin API routes"</div>
                        </div>
                        <div style="padding: var(--sp-md); background: var(--bg-2); border-radius: var(--r-md); border: 1px solid var(--border-subtle)">
                            <div style="font-size: 12px; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; margin-bottom: var(--sp-sm)">"OIDC Integration"</div>
                            <div style="font-size: 14px; color: var(--text-1)">"Not configured"</div>
                            <div style="font-size: 12px; color: var(--text-3); margin-top: var(--sp-sm)">"Configure via environment variables"</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="card" style="margin-bottom: var(--sp-xl)">
                <div class="card-header">
                    <span class="card-title">"API Keys"</span>
                </div>
                <div class="card-body">
                    <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                        "API key management is coming soon. Currently, authentication is handled via Bearer tokens."
                    </p>
                    <div style="padding: var(--sp-md); background: var(--bg-2); border-radius: var(--r-md); border: 1px solid var(--border-subtle); border-left: 3px solid var(--gold)">
                        <div style="font-size: 13px; color: var(--text-2); font-style: italic">"Self-service API key generation and revocation will be available in a future release."</div>
                    </div>
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

            <div class="card" style="margin-bottom: var(--sp-xl)">
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

            <CorsOriginsCard />
            <CatalogInstallCard />
        </div>
    }
}

/// Card that lets operators view and update the CORS allowed origins.
/// Changes are persisted to the DB and applied live — no restart needed.
#[component]
fn CorsOriginsCard() -> impl IntoView {
    let origins_resource = Resource::new(|| (), |_| get_cors_origins());
    let textarea_value: RwSignal<Option<String>> = RwSignal::new(None);
    let saving = RwSignal::new(false);
    let save_result: RwSignal<Option<Result<(), String>>> = RwSignal::new(None);

    let on_save = move |_| {
        let value = textarea_value.get().unwrap_or_default();
        saving.set(true);
        save_result.set(None);
        spawn_local(async move {
            match update_cors_origins(value).await {
                Ok(()) => {
                    save_result.set(Some(Ok(())));
                    // Refresh the displayed value from the server.
                    origins_resource.refetch();
                }
                Err(e) => {
                    save_result.set(Some(Err(e.to_string())));
                }
            }
            saving.set(false);
        });
    };

    view! {
        <div class="card" style="margin-bottom: var(--sp-xl)">
            <div class="card-header">
                <span class="card-title">"CORS Allowed Origins"</span>
            </div>
            <div class="card-body">
                <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                    "Enter the origins (one per line) that are allowed to make cross-origin \
                     requests to this registry's API.  Changes take effect immediately without \
                     restarting the server."
                </p>
                <Suspense fallback=|| view! { <div class="loading">"Loading…"</div> }>
                    {move || origins_resource.get().map(|result| {
                        let initial = match result {
                            Ok(ref s) => s.clone(),
                            Err(_) => String::new(),
                        };
                        // Seed the signal on first load only.
                        if textarea_value.get_untracked().is_none() {
                            textarea_value.set(Some(initial.clone()));
                        }
                        view! {
                            <textarea
                                class="form-input"
                                rows="4"
                                placeholder="https://app.example.com\nhttps://localhost:7890"
                                style="font-family: var(--font-mono); font-size: 12px; width: 100%; \
                                       box-sizing: border-box; resize: vertical"
                                prop:value=move || textarea_value.get().unwrap_or(initial.clone())
                                on:input=move |ev| {
                                    textarea_value.set(Some(event_target_value(&ev)));
                                }
                            />
                        }.into_any()
                    })}
                </Suspense>
                <div style="display: flex; align-items: center; gap: var(--sp-md); margin-top: var(--sp-md); flex-wrap: wrap">
                    <button
                        class="btn btn-primary"
                        disabled=move || saving.get()
                        on:click=on_save
                    >
                        {move || if saving.get() { "Saving…" } else { "Save Origins" }}
                    </button>
                    {move || save_result.get().map(|r| match r {
                        Ok(()) => view! {
                            <span style="font-size: 13px; color: var(--teal)">"✓ Saved — active immediately"</span>
                        }.into_any(),
                        Err(e) => view! {
                            <span style="font-size: 13px; color: var(--red)">"✗ " {e}</span>
                        }.into_any(),
                    })}
                </div>
                <p style="font-size: 12px; color: var(--text-3); margin-top: var(--sp-sm)">
                    "Example: " <code style="font-family: var(--font-mono)">"https://registry.example.com"</code>
                    " · Format: one exact origin per line (scheme + host + port, no trailing slash)"
                </p>
            </div>
        </div>
    }
}

#[component]
fn CatalogInstallCard() -> impl IntoView {
    let installing = RwSignal::new(false);
    let install_status: RwSignal<Option<Result<String, String>>> = RwSignal::new(None);

    let on_install = move |_| {
        installing.set(true);
        install_status.set(None);
        spawn_local(async move {
            match api::install_catalog_agents().await {
                Ok(result) => {
                    install_status.set(Some(Ok(format!(
                        "✓ Installed {} agents ({} already present{})",
                        result.installed,
                        result.skipped,
                        if result.errors > 0 {
                            format!(", {} errors", result.errors)
                        } else {
                            String::new()
                        }
                    ))));
                }
                Err(e) => {
                    install_status.set(Some(Err(e.to_string())));
                }
            }
            installing.set(false);
        });
    };

    view! {
        <div class="card">
            <div class="card-header">
                <span class="card-title">"PAP Catalog Agents"</span>
            </div>
            <div class="card-body">
                <p style="font-size: 13px; color: var(--text-2); margin-bottom: var(--sp-md)">
                    "Install the shared PAP agent catalog (200+ agents covering search, travel, finance, science, and more) into this registry. "
                    "Each agent receives a deterministic operator keypair — reinstalling is safe and idempotent."
                </p>
                <div style="display: flex; align-items: center; gap: var(--sp-sm); margin-bottom: var(--sp-md); font-size: 12px; color: var(--text-3)">
                    <span style="font-family: var(--font-mono);">"Catalog path:"</span>
                    <code style="font-family: var(--font-mono); color: var(--purple); background: var(--purple-muted); padding: 2px 6px; border-radius: 4px">
                        "$PAP_CATALOG_PATH"
                    </code>
                    <span>"or"</span>
                    <code style="font-family: var(--font-mono); color: var(--text-2); background: var(--bg-2); padding: 2px 6px; border-radius: 4px">
                        "crates/pap-agents/catalog"
                    </code>
                </div>

                <div style="display: flex; align-items: center; gap: var(--sp-md); flex-wrap: wrap">
                    <button
                        class="btn btn-primary"
                        disabled=move || installing.get()
                        on:click=on_install
                    >
                        {move || if installing.get() { "⏳ Installing…" } else { "Install Catalog Agents" }}
                    </button>

                    {move || install_status.get().map(|result| match result {
                        Ok(msg) => view! {
                            <span style="font-size: 13px; color: var(--teal)">{msg}</span>
                        }.into_any(),
                        Err(e) => view! {
                            <span style="font-size: 13px; color: var(--red)">"✗ " {e}</span>
                        }.into_any(),
                    })}
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
