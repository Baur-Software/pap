use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::registry::agent_card::AgentCard;
use crate::state::registry::RegistryState;
use papillion_shared::{AgentInfo, RegistryInfo};

#[component]
pub fn RegistryBrowser() -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    let is_connected = move || registry.info.get().is_some();
    let agents = move || registry.agents.get();
    let is_loading = move || registry.loading.get();
    let error_msg = move || registry.error.get();

    let on_sync = move |_| {
        let url = registry.current_url.get();
        if url.is_empty() {
            return;
        }
        let action = registry.action_filter.get();
        if action.is_empty() {
            return;
        }

        registry.loading.set(true);
        registry.error.set(None);

        spawn_local(async move {
            #[derive(serde::Serialize)]
            struct SyncArgs {
                registry_url: String,
                action: String,
            }

            match bridge::invoke::<SyncArgs, RegistryInfo>(
                "sync_agents",
                &SyncArgs {
                    registry_url: url.clone(),
                    action: action.clone(),
                },
            )
            .await
            {
                Ok(info) => {
                    registry.info.set(Some(info));
                    // Now fetch the agent list
                    #[derive(serde::Serialize)]
                    struct ListArgs {
                        registry_url: String,
                        action: String,
                    }
                    match bridge::invoke::<ListArgs, Vec<AgentInfo>>(
                        "search_agents",
                        &ListArgs {
                            registry_url: url,
                            action,
                        },
                    )
                    .await
                    {
                        Ok(agents) => registry.agents.set(agents),
                        Err(e) => registry.error.set(Some(e)),
                    }
                }
                Err(e) => registry.error.set(Some(e)),
            }
            registry.loading.set(false);
        });
    };

    view! {
        <div>
            <Show when=is_connected fallback=move || view! {
                <div style="text-align: center; padding: 48px 0; color: var(--text-secondary);">
                    <p style="font-size: 16px; margin-bottom: 8px;">"Enter a registry URL in the address bar"</p>
                    <p style="font-size: 13px;">"e.g. pap://localhost:8080"</p>
                </div>
            }>
                <div style="margin-bottom: 16px; display: flex; gap: 8px; align-items: center;">
                    <input
                        type="text"
                        placeholder="Filter by action (e.g. schema:SearchAction)"
                        style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 6px 12px; color: var(--text-primary); font-size: 13px; outline: none;"
                        prop:value=move || registry.action_filter.get()
                        on:input=move |ev| {
                            use wasm_bindgen::JsCast;
                            let target: web_sys::EventTarget = ev.target().unwrap();
                            let input: web_sys::HtmlInputElement = target.unchecked_into();
                            registry.action_filter.set(input.value());
                        }
                    />
                    <button class="btn btn-primary" on:click=on_sync>
                        "Sync"
                    </button>
                </div>

                {move || error_msg().map(|e| view! {
                    <div style="background: rgba(225, 112, 85, 0.1); border: 1px solid var(--error); border-radius: 6px; padding: 8px 12px; margin-bottom: 12px; font-size: 12px; color: var(--error);">
                        {e}
                    </div>
                })}

                <Show when=is_loading fallback=|| ()>
                    <div style="text-align: center; padding: 24px; color: var(--text-secondary);">
                        "Loading..."
                    </div>
                </Show>

                {move || {
                    let agent_list = agents();
                    if agent_list.is_empty() && !is_loading() {
                        Some(view! {
                            <div style="text-align: center; padding: 24px; color: var(--text-secondary);">
                                "No agents found. Try syncing with an action type."
                            </div>
                        })
                    } else {
                        None
                    }
                }}

                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;">
                    {move || agents().into_iter().map(|agent| view! {
                        <AgentCard agent=agent />
                    }).collect::<Vec<_>>()}
                </div>

                {move || registry.info.get().map(|info| view! {
                    <div style="margin-top: 16px; font-size: 11px; color: var(--text-secondary);">
                        {info.agent_count}" agents, "{info.peer_count}" peers"
                    </div>
                })}
            </Show>
        </div>
    }
}
