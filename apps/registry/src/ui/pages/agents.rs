use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::ui::api::{self, AgentEntry};

const PER_PAGE: u32 = 20;

#[component]
pub fn AgentsPage() -> impl IntoView {
    let query = RwSignal::new(String::new());
    let page = RwSignal::new(1u32);
    let show_register = RwSignal::new(false);
    let refresh_key = RwSignal::new(0u32);

    let agents = Resource::new(
        move || (query.get(), page.get(), refresh_key.get()),
        |(q, pg, _)| async move {
            api::list_agents(if q.is_empty() { None } else { Some(q) }, pg, PER_PAGE).await
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
                    <div style="display:flex; gap:8px;">
                        <a href="/agents/design" class="btn btn-secondary">"+ Design Agent"</a>
                        <button class="btn btn-primary" on:click=move |_| show_register.set(true)>
                            "+ Register Agent"
                        </button>
                    </div>
                </div>
            </div>

            <div class="filter-bar">
                <input
                    class="filter-input"
                    placeholder="Search by name, provider, or capability…"
                    prop:value=move || query.get()
                    on:input=move |e| {
                        let val = event_target_value(&e);
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

            <Suspense fallback=|| view! { <div class="loading">"Loading agents…"</div> }>
                {move || agents.get().map(|result| match result {
                    Err(e) => view! {
                        <div class="error-banner">"Error: " {e.to_string()}</div>
                    }.into_any(),
                    Ok(resp) => {
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
                                            <AgentCard
                                                entry=entry.clone()
                                                on_remove=move || reload()
                                            />
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
                })}
            </Suspense>

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
fn AgentCard(entry: AgentEntry, #[prop(into)] on_remove: Callback<()>) -> impl IntoView {
    let hash = entry.hash.clone();
    let hash_display = {
        let h = &hash;
        if h.len() > 16 {
            format!("{}…", &h[..16])
        } else {
            h.clone()
        }
    };
    let ad = entry.ad;
    let name = ad.name.clone();
    let provider_name = ad.provider.name.clone();
    let provider_did = ad.provider.did.clone();
    let capabilities = ad.capability.clone();
    let returns = ad.returns.clone();
    let disclosure = ad.requires_disclosure.clone();
    let signed_by = ad.signed_by.clone();

    let error = RwSignal::new(None::<String>);
    let remove_action = Action::new({
        let hash = hash.clone();
        move |_: &()| {
            let hash = hash.clone();
            async move { api::remove_agent(hash).await }
        }
    });

    // React to action completion
    Effect::new(move || match remove_action.value().get() {
        Some(Ok(())) => on_remove.run(()),
        Some(Err(e)) => error.set(Some(e.to_string())),
        None => {}
    });

    let removing = move || remove_action.pending().get();

    // Sandbox toggle — state is pre-loaded in list_agents to avoid per-card
    // server function calls during SSR (which serialized N DB round-trips).
    // Persisted immediately on toggle but only takes effect on server restart.
    let sandbox_enabled = RwSignal::new(entry.sandbox_enabled);
    let sandbox_error = RwSignal::new(None::<String>);
    let on_sandbox_toggle = {
        let hash_for_toggle = hash.clone();
        move |_| {
            let new_val = !sandbox_enabled.get_untracked();
            let hash = hash_for_toggle.clone();
            spawn_local(async move {
                match api::set_agent_sandbox_enabled(hash, new_val).await {
                    Ok(()) => sandbox_enabled.set(new_val),
                    Err(e) => sandbox_error.set(Some(e.to_string())),
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
                <div style="display:flex; gap: var(--sp-sm); align-items:center">
                    // Sandbox toggle — state arrives pre-loaded in the entry prop.
                    <label
                        title="Toggle OS-level sandbox isolation (restart required to apply)"
                        style="display:flex; align-items:center; gap:4px; cursor:pointer; user-select:none"
                    >
                        <input
                            type="checkbox"
                            prop:checked=move || sandbox_enabled.get()
                            on:change=on_sandbox_toggle.clone()
                        />
                        <span style="font-size:11px; color: var(--text-2)">"Sandbox*"</span>
                    </label>
                    <button
                        class="btn btn-danger btn-sm"
                        disabled=removing
                        on:click=move |_| { remove_action.dispatch(()); }
                    >
                        {move || if removing() { "…" } else { "Remove" }}
                    </button>
                </div>
            </div>

            {move || error.get().map(|e| view! {
                <div class="error-banner" style="margin-top: var(--sp-xs)">{e}</div>
            })}
            {move || sandbox_error.get().map(|e| view! {
                <div class="error-banner" style="margin-top: var(--sp-xs)">"Sandbox toggle: " {e}</div>
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

    let register_action = Action::new(move |json: &String| {
        let json = json.clone();
        async move { api::register_agent_json(json).await }
    });

    Effect::new(move || match register_action.value().get() {
        Some(Ok(_hash)) => on_success.run(()),
        Some(Err(e)) => error.set(Some(e.to_string())),
        None => {}
    });

    let submitting = move || register_action.pending().get();

    let do_submit = move |_| {
        let json = json_input.get();
        if json.trim().is_empty() {
            error.set(Some("Advertisement JSON is required.".into()));
            return;
        }
        error.set(None);
        register_action.dispatch(json);
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
                        disabled=submitting
                        on:click=do_submit
                    >
                        {move || if submitting() { "Registering…" } else { "Register" }}
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
