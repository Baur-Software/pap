use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::api::{self, AgentEntry, AgentListResponse};

const PER_PAGE: u32 = 20;

#[component]
pub fn AgentsPage() -> impl IntoView {
    let query = RwSignal::new(String::new());
    let page = RwSignal::new(1u32);
    let show_register = RwSignal::new(false);
    // Incrementing this forces a re-fetch (used by Refresh button and on_remove).
    let refresh_key = RwSignal::new(0u32);

    // create_resource tracks (query, page, refresh_key) as its source and re-fetches
    // automatically when any of them changes — one fetch per source change, no double-fetches.
    let agents = create_resource(
        move || (query.get(), page.get(), refresh_key.get()),
        |(q, pg, _)| async move {
            let q_ref = if q.is_empty() { None } else { Some(q.as_str()) };
            api::fetch_agents(q_ref, pg, PER_PAGE).await
        },
    );

    let reload = move || refresh_key.update(|n| *n += 1);

    view! {
        <div class="page">
            <div class="page-header">
                <div style="display:flex; align-items:center; justify-content:space-between">
                    <div>
                        <h1 class="page-title">"Agents"</h1>
                        <p class="page-subtitle">"All registered agent advertisements in this node's registry."</p>
                    </div>
                    <button class="btn btn-primary" on:click=move |_| show_register.set(true)>
                        "+ Register Agent"
                    </button>
                </div>
            </div>

            <div class="filter-bar">
                <input
                    class="filter-input"
                    placeholder="Search by name, provider, or capability…"
                    prop:value=move || query.get()
                    on:input=move |e| {
                        let val = event_target_value(&e);
                        // batch ensures query + page reset fire as one reactive update
                        batch(move || {
                            query.set(val);
                            page.set(1);
                        });
                    }
                />
                <button class="btn btn-secondary" on:click=move |_| reload()>
                    "↺ Refresh"
                </button>
            </div>

            {move || match agents.get() {
                None => view! { <div class="loading">"Loading agents…"</div> }.into_any(),
                Some(Err(e)) => view! {
                    <div class="error-banner">"Error: " {e}</div>
                }.into_any(),
                Some(Ok(resp)) => {
                    if resp.items.is_empty() {
                        view! {
                            <div class="empty-state">
                                <div class="empty-state-icon">"⬡"</div>
                                <div class="empty-state-title">"No agents found"</div>
                                <p style="font-size:13px; color: var(--text-3)">
                                    {if query.get().is_empty() {
                                        "No agents are registered yet. Click \"Register Agent\" to add one."
                                    } else {
                                        "No agents match your search."
                                    }}
                                </p>
                            </div>
                        }.into_any()
                    } else {
                        let total = resp.total;
                        let total_pages = resp.total_pages;
                        view! {
                            <div>
                                <div class="agent-list">
                                    {resp.items.into_iter().map(|entry| view! {
                                        <AgentCard entry=entry.clone() on_remove=move || reload() />
                                    }).collect::<Vec<_>>()}
                                </div>
                                <div class="pagination">
                                    <button
                                        class="btn btn-secondary btn-sm"
                                        disabled=move || page.get() <= 1
                                        on:click=move |_| page.update(|p| *p -= 1)
                                    >
                                        "← Prev"
                                    </button>
                                    <span class="pagination-info">
                                        "Page " {move || page.get()} " of " {total_pages}
                                        " (" {total} " total)"
                                    </span>
                                    <button
                                        class="btn btn-secondary btn-sm"
                                        disabled=move || page.get() >= total_pages
                                        on:click=move |_| page.update(|p| *p += 1)
                                    >
                                        "Next →"
                                    </button>
                                </div>
                            </div>
                        }.into_any()
                    }
                }
            }}

            {move || if show_register.get() {
                view! {
                    <RegisterModal
                        on_close=move || show_register.set(false)
                        on_success=move || { show_register.set(false); reload(); }
                    />
                }.into_any()
            } else {
                view! { <span /> }.into_any()
            }}
        </div>
    }
}

#[component]
fn AgentCard(
    entry: AgentEntry,
    #[prop(into)] on_remove: Callback<()>,
) -> impl IntoView {
    let hash = entry.hash.clone();
    let hash_display = {
        let h = &hash;
        if h.len() > 16 { format!("{}…", &h[..16]) } else { h.clone() }
    };
    let ad = entry.ad;
    let name = ad.name.clone();
    let provider_name = ad.provider.name.clone();
    let provider_did = ad.provider.did.clone();
    let capabilities = ad.capability.clone();
    let returns = ad.returns.clone();
    let disclosure = ad.requires_disclosure.clone();
    let signed_by = ad.signed_by.clone();

    let removing = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    let do_remove = {
        let hash = hash.clone();
        move |_| {
            let hash = hash.clone();
            removing.set(true);
            spawn_local(async move {
                match api::remove_agent(&hash).await {
                    Ok(()) => on_remove.run(()),
                    Err(e) => {
                        error.set(Some(e));
                        removing.set(false);
                    }
                }
            });
        }
    };

    view! {
        <div class="agent-card">
            <div style="display:flex; justify-content:space-between; align-items:flex-start">
                <div style="flex:1; min-width:0">
                    <div class="agent-name">{name}</div>
                    <div class="agent-provider">
                        {provider_name} " · " {provider_did}
                    </div>
                </div>
                <button
                    class="btn btn-danger btn-sm"
                    disabled=move || removing.get()
                    on:click=do_remove
                >
                    {move || if removing.get() { "…" } else { "Remove" }}
                </button>
            </div>

            {move || error.get().map(|e| view! {
                <div class="error-banner" style="margin-top: var(--sp-xs)">{e}</div>
            })}

            <div class="agent-meta">
                {capabilities.iter().map(|c| view! {
                    <span class="tag tag-action">{c.clone()}</span>
                }).collect::<Vec<_>>()}
                {returns.iter().map(|r| view! {
                    <span class="tag tag-returns">{r.clone()}</span>
                }).collect::<Vec<_>>()}
                {disclosure.iter().map(|d| view! {
                    <span class="tag tag-disclosure">{d.clone()}</span>
                }).collect::<Vec<_>>()}
            </div>

            <div class="agent-did">"Signed by: " {signed_by}</div>
            <div class="agent-hash">"Hash: " {hash_display}</div>
        </div>
    }
}

#[component]
fn RegisterModal(
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_success: Callback<()>,
) -> impl IntoView {
    let json_input = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let submitting = RwSignal::new(false);

    let do_submit = move |_| {
        let json = json_input.get();
        if json.trim().is_empty() {
            error.set(Some("Advertisement JSON is required.".into()));
            return;
        }
        submitting.set(true);
        error.set(None);
        spawn_local(async move {
            match serde_json::from_str::<crate::api::AgentAdvertisement>(&json) {
                Err(e) => {
                    error.set(Some(format!("Invalid JSON: {}", e)));
                    submitting.set(false);
                }
                Ok(_) => {
                    let window = web_sys::window().unwrap();
                    let mut opts = web_sys::RequestInit::new();
                    opts.set_method("POST");
                    opts.set_mode(web_sys::RequestMode::SameOrigin);
                    opts.set_body(&wasm_bindgen::JsValue::from_str(&json));
                    match web_sys::Request::new_with_str_and_init("/api/agents", &opts) {
                        Err(e) => {
                            error.set(Some(format!("Request error: {:?}", e)));
                            submitting.set(false);
                        }
                        Ok(req) => {
                            let _ = req.headers().set("Content-Type", "application/json");
                            match wasm_bindgen_futures::JsFuture::from(
                                window.fetch_with_request(&req),
                            )
                            .await
                            {
                                Err(e) => {
                                    error.set(Some(format!("Fetch error: {:?}", e)));
                                    submitting.set(false);
                                }
                                Ok(resp_val) => {
                                    let resp: web_sys::Response =
                                        resp_val.dyn_into().unwrap();
                                    if resp.ok() {
                                        on_success.run(());
                                    } else {
                                        error.set(Some(format!(
                                            "Server error: HTTP {}",
                                            resp.status()
                                        )));
                                        submitting.set(false);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    };

    view! {
        <div class="modal-backdrop">
            <div class="modal">
                <div class="modal-title">"Register Agent Advertisement"</div>
                <div class="form-group">
                    <label class="form-label">"Advertisement JSON"</label>
                    <textarea
                        class="form-textarea"
                        placeholder=PLACEHOLDER_AD
                        prop:value=move || json_input.get()
                        on:input=move |e| json_input.set(event_target_value(&e))
                    />
                    <div class="form-hint">
                        "Paste a signed AgentAdvertisement JSON-LD object. Must include a valid Ed25519 signature."
                    </div>
                </div>

                {move || error.get().map(|e| view! {
                    <div class="error-banner">{e}</div>
                })}

                <div class="modal-actions">
                    <button class="btn btn-secondary" on:click=move |_| on_close.run(())>
                        "Cancel"
                    </button>
                    <button
                        class="btn btn-primary"
                        disabled=move || submitting.get()
                        on:click=do_submit
                    >
                        {move || if submitting.get() { "Registering…" } else { "Register" }}
                    </button>
                </div>
            </div>
        </div>
    }
}

const PLACEHOLDER_AD: &str = r#"{
  "@context": "https://schema.org",
  "@type": "schema:Service",
  "name": "My Agent",
  "provider": { "@type": "schema:Organization", "name": "Acme", "did": "did:key:z..." },
  "capability": ["schema:SearchAction"],
  "object_types": [],
  "requires_disclosure": [],
  "returns": ["schema:SearchResult"],
  "ttl_min": 300,
  "signed_by": "did:key:z...",
  "signature": "..."
}"#;
