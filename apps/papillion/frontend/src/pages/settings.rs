use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::address_bar::AddressBar;
use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::{
    ExportedKey, KeyBackupStatus, LlmProvider, OrchestratorConfig, SuccessorDesignation,
};

#[component]
pub fn SettingsPage() -> impl IntoView {
    let active_tab = RwSignal::new("general".to_string());

    view! {
        <div>
            <h2 class="page-title">"Settings"</h2>
            <div class="settings-tabs">
                <button
                    class=move || if active_tab.get() == "general" { "settings-tab active" } else { "settings-tab" }
                    on:click=move |_| active_tab.set("general".into())
                >"General"</button>
                <button
                    class=move || if active_tab.get() == "identity" { "settings-tab active" } else { "settings-tab" }
                    on:click=move |_| active_tab.set("identity".into())
                >"Identity"</button>
                <button
                    class=move || if active_tab.get() == "advanced" { "settings-tab active" } else { "settings-tab" }
                    on:click=move |_| active_tab.set("advanced".into())
                >"Advanced"</button>
            </div>

            <Show when=move || active_tab.get() == "general">
                <GeneralTab />
            </Show>
            <Show when=move || active_tab.get() == "identity">
                <IdentityTab />
            </Show>
            <Show when=move || active_tab.get() == "advanced">
                <AdvancedTab />
            </Show>
        </div>
    }
}

#[component]
fn GeneralTab() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let selected = RwSignal::new(String::new());
    let ollama_endpoint = RwSignal::new("http://localhost:11434".to_string());
    let ollama_model = RwSignal::new("llama3.2:1b".to_string());
    let openai_endpoint = RwSignal::new(String::new());
    let openai_key = RwSignal::new(String::new());
    let openai_model = RwSignal::new(String::new());
    let saved_msg = RwSignal::new(false);

    // Initialize from current config
    Effect::new(move || {
        let config = orchestrator.config.get();
        match &config.llm_provider {
            LlmProvider::Ollama { endpoint, model } => {
                selected.set("ollama".into());
                ollama_endpoint.set(endpoint.clone());
                ollama_model.set(model.clone());
            }
            LlmProvider::OpenAiCompatible {
                endpoint,
                api_key,
                model,
            } => {
                selected.set("openai".into());
                openai_endpoint.set(endpoint.clone());
                openai_key.set(api_key.clone());
                openai_model.set(model.clone());
            }
            LlmProvider::None => selected.set("none".into()),
        }
    });

    let save = move |_| {
        let provider = match selected.get().as_str() {
            "ollama" => LlmProvider::Ollama {
                endpoint: ollama_endpoint.get(),
                model: ollama_model.get(),
            },
            "openai" => LlmProvider::OpenAiCompatible {
                endpoint: openai_endpoint.get(),
                api_key: openai_key.get(),
                model: openai_model.get(),
            },
            _ => LlmProvider::None,
        };

        let config = OrchestratorConfig {
            llm_provider: provider,
            mandate_ttl_hours: orchestrator.config.get().mandate_ttl_hours,
            auto_approve_zero_disclosure: orchestrator.config.get().auto_approve_zero_disclosure,
        };

        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, OrchestratorConfig>(
                "configure_orchestrator",
                &serde_json::json!({ "config": config }),
            )
            .await
            {
                Ok(saved_config) => {
                    orchestrator.config.set(saved_config);
                    saved_msg.set(true);
                }
                Err(e) => {
                    web_sys::console::error_1(&format!("Failed to save: {e}").into());
                }
            }
        });
    };

    view! {
        <div class="card">
            <h3 style="font-size: 14px; margin-bottom: 12px;">"LLM Provider"</h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 16px;">
                "Configure the language model that powers the orchestrator."
            </p>
            <select
                style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; color: var(--text-primary); font-size: 13px; margin-bottom: 16px;"
                on:change=move |ev| selected.set(event_target_value(&ev))
                prop:value=move || selected.get()
            >
                <option value="none">"None (Demo Mode)"</option>
                <option value="ollama">"Ollama"</option>
                <option value="openai">"OpenAI-compatible"</option>
            </select>

            <Show when=move || selected.get() == "ollama">
                <div class="setup-inputs">
                    <label>"Endpoint"</label>
                    <input
                        type="text"
                        prop:value=move || ollama_endpoint.get()
                        on:input=move |ev| ollama_endpoint.set(event_target_value(&ev))
                    />
                    <label>"Model"</label>
                    <input
                        type="text"
                        prop:value=move || ollama_model.get()
                        on:input=move |ev| ollama_model.set(event_target_value(&ev))
                    />
                </div>
            </Show>

            <Show when=move || selected.get() == "openai">
                <div class="setup-inputs">
                    <label>"Endpoint"</label>
                    <input
                        type="text"
                        placeholder="https://api.openai.com/v1"
                        prop:value=move || openai_endpoint.get()
                        on:input=move |ev| openai_endpoint.set(event_target_value(&ev))
                    />
                    <label>"API Key"</label>
                    <input
                        type="password"
                        placeholder="sk-..."
                        prop:value=move || openai_key.get()
                        on:input=move |ev| openai_key.set(event_target_value(&ev))
                    />
                    <label>"Model"</label>
                    <input
                        type="text"
                        placeholder="gpt-4o"
                        prop:value=move || openai_model.get()
                        on:input=move |ev| openai_model.set(event_target_value(&ev))
                    />
                </div>
            </Show>

            <div style="display: flex; align-items: center; gap: 12px; margin-top: 16px;">
                <button class="btn btn-primary" on:click=save>"Save"</button>
                <Show when=move || saved_msg.get()>
                    <span style="font-size: 12px; color: var(--success);">"Saved!"</span>
                </Show>
            </div>
        </div>
    }
}

#[component]
fn IdentityTab() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let exported_key = RwSignal::new(None::<String>);
    let show_export = RwSignal::new(false);
    let show_import = RwSignal::new(false);
    let import_input = RwSignal::new(String::new());
    let import_error = RwSignal::new(None::<String>);
    let show_add_successor = RwSignal::new(false);
    let succ_did = RwSignal::new(String::new());
    let succ_rel = RwSignal::new("executor".to_string());
    let succ_notes = RwSignal::new(String::new());

    // Load backup status + successors on mount
    Effect::new(move || {
        spawn_local(async move {
            if let Ok(status) =
                bridge::invoke_no_args::<KeyBackupStatus>("get_key_backup_status").await
            {
                identity.backed_up.set(status.backed_up);
            }
            if let Ok(suc) =
                bridge::invoke_no_args::<Vec<SuccessorDesignation>>("list_successors").await
            {
                identity.successors.set(suc);
            }
        });
    });

    let handle_export = move |_| {
        spawn_local(async move {
            match bridge::invoke_no_args::<ExportedKey>("export_key").await {
                Ok(key) => {
                    exported_key.set(Some(key.seed_b64));
                    identity.backed_up.set(true);
                    show_export.set(true);
                }
                Err(e) => web_sys::console::error_1(&e.into()),
            }
        });
    };

    let handle_import = move |_| {
        let seed = import_input.get();
        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, papillion_shared::IdentityInfo>(
                "import_key",
                &serde_json::json!({ "seedB64": seed }),
            )
            .await
            {
                Ok(info) => {
                    identity.info.set(Some(info));
                    identity.backed_up.set(true);
                    show_import.set(false);
                    import_error.set(None);
                }
                Err(e) => import_error.set(Some(e)),
            }
        });
    };

    let handle_add_successor = move |_| {
        let did = succ_did.get();
        let rel = succ_rel.get();
        let notes = succ_notes.get();
        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, Vec<SuccessorDesignation>>(
                "add_successor",
                &serde_json::json!({
                    "successorDid": did,
                    "relationship": rel,
                    "notes": notes
                }),
            )
            .await
            {
                Ok(suc) => {
                    identity.successors.set(suc);
                    succ_did.set(String::new());
                    succ_notes.set(String::new());
                    show_add_successor.set(false);
                }
                Err(e) => web_sys::console::error_1(&e.into()),
            }
        });
    };

    view! {
        // Backup warning
        <Show when=move || !identity.backed_up.get()>
            <div class="backup-warning">
                <strong>"Your key has not been backed up!"</strong>
                <p>"If you lose this device, you will lose your identity and all mandates. Export your key now."</p>
            </div>
        </Show>

        // Identity info
        <div class="card" style="margin-bottom: 16px;">
            <h3 style="font-size: 14px; margin-bottom: 12px;">"Identity"</h3>
            <Show
                when=move || identity.info.get().is_some()
                fallback=|| view! {
                    <p style="color: var(--text-secondary);">"Loading identity..."</p>
                }
            >
                {move || identity.info.get().map(|info| view! {
                    <div>
                        <div style="margin-bottom: 8px;">
                            <span style="color: var(--text-secondary); font-size: 12px;">"DID: "</span>
                            <code style="font-size: 12px; word-break: break-all;">{info.did}</code>
                        </div>
                        <div>
                            <span style="color: var(--text-secondary); font-size: 12px;">"Public Key: "</span>
                            <code style="font-size: 12px; word-break: break-all;">{info.public_key_b64}</code>
                        </div>
                    </div>
                })}
            </Show>

            <div style="display: flex; gap: 8px; margin-top: 16px;">
                <button class="btn btn-primary" on:click=handle_export>"Export Key"</button>
                <button class="btn" style="background: var(--bg-tertiary); color: var(--text-secondary);"
                    on:click=move |_| show_import.update(|v| *v = !*v)
                >"Import Key"</button>
            </div>
        </div>

        // Export display
        <Show when=move || show_export.get()>
            <div class="card" style="margin-bottom: 16px;">
                <h3 style="font-size: 14px; margin-bottom: 8px;">"Exported Key"</h3>
                <p style="font-size: 12px; color: var(--warning); margin-bottom: 8px;">
                    "Store this securely. Anyone with this key controls your identity."
                </p>
                <code class="key-display">{move || exported_key.get().unwrap_or_default()}</code>
            </div>
        </Show>

        // Import form
        <Show when=move || show_import.get()>
            <div class="card" style="margin-bottom: 16px;">
                <h3 style="font-size: 14px; margin-bottom: 8px;">"Import Key"</h3>
                <p style="font-size: 12px; color: var(--warning); margin-bottom: 8px;">
                    "This will replace your current identity."
                </p>
                <input
                    type="text"
                    style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; color: var(--text-primary); font-size: 13px; font-family: 'SF Mono', 'Fira Code', monospace; margin-bottom: 8px;"
                    placeholder="Paste base64url seed..."
                    prop:value=move || import_input.get()
                    on:input=move |ev| import_input.set(event_target_value(&ev))
                />
                <Show when=move || import_error.get().is_some()>
                    <p style="color: var(--error); font-size: 12px; margin-bottom: 8px;">
                        {move || import_error.get().unwrap_or_default()}
                    </p>
                </Show>
                <button class="btn btn-primary" on:click=handle_import>"Import"</button>
            </div>
        </Show>

        // Successor designations
        <div class="card">
            <h3 style="font-size: 14px; margin-bottom: 4px;">"Designated Successors"</h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                "Designate DIDs that could inherit your principal authority \u{2014} for estate planning, organizational continuity, or recovery."
            </p>

            <For
                each=move || identity.successors.get()
                key=|s| s.successor_did.clone()
                let:successor
            >
                {
                    let did = successor.successor_did.clone();
                    let did_for_remove = successor.successor_did.clone();
                    let rel = successor.relationship.clone();
                    let notes = successor.notes.clone();
                    view! {
                        <div class="successor-entry">
                            <div style="flex: 1; min-width: 0;">
                                <code style="font-size: 11px; word-break: break-all;">{did}</code>
                            </div>
                            <span class="badge badge-accent">{rel}</span>
                            <Show when={
                                let n = notes.clone();
                                move || !n.is_empty()
                            }>
                                <span style="font-size: 11px; color: var(--text-secondary);">{notes.clone()}</span>
                            </Show>
                            <button
                                class="btn"
                                style="padding: 2px 8px; font-size: 11px; background: var(--bg-tertiary); color: var(--error);"
                                on:click=move |_| {
                                    let did = did_for_remove.clone();
                                    spawn_local(async move {
                                        if let Ok(suc) = bridge::invoke::<serde_json::Value, Vec<SuccessorDesignation>>(
                                            "remove_successor",
                                            &serde_json::json!({ "successorDid": did }),
                                        ).await {
                                            identity.successors.set(suc);
                                        }
                                    });
                                }
                            >"Remove"</button>
                        </div>
                    }
                }
            </For>

            <Show
                when=move || show_add_successor.get()
                fallback=move || view! {
                    <button
                        class="btn"
                        style="margin-top: 8px; background: var(--bg-tertiary); color: var(--text-secondary);"
                        on:click=move |_| show_add_successor.set(true)
                    >"Add Successor"</button>
                }
            >
                <div class="setup-inputs" style="margin-top: 12px;">
                    <label>"Successor DID"</label>
                    <input
                        type="text"
                        placeholder="did:key:z..."
                        prop:value=move || succ_did.get()
                        on:input=move |ev| succ_did.set(event_target_value(&ev))
                    />
                    <label>"Relationship"</label>
                    <select
                        style="background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; color: var(--text-primary); font-size: 13px;"
                        on:change=move |ev| succ_rel.set(event_target_value(&ev))
                        prop:value=move || succ_rel.get()
                    >
                        <option value="executor">"Executor"</option>
                        <option value="spouse">"Spouse"</option>
                        <option value="descendant">"Descendant"</option>
                        <option value="trusted-friend">"Trusted Friend"</option>
                        <option value="organization">"Organization"</option>
                    </select>
                    <label>"Notes"</label>
                    <input
                        type="text"
                        placeholder="Optional notes..."
                        prop:value=move || succ_notes.get()
                        on:input=move |ev| succ_notes.set(event_target_value(&ev))
                    />
                    <div style="display: flex; gap: 8px;">
                        <button class="btn btn-primary" on:click=handle_add_successor>"Save"</button>
                        <button
                            class="btn"
                            style="background: var(--bg-tertiary); color: var(--text-secondary);"
                            on:click=move |_| show_add_successor.set(false)
                        >"Cancel"</button>
                    </div>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn AdvancedTab() -> impl IntoView {
    view! {
        <div>
            <div class="card" style="margin-bottom: 16px;">
                <h3 style="font-size: 14px; margin-bottom: 12px;">"Registry Browser"</h3>
                <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                    "Navigate PAP registries directly using protocol URLs."
                </p>
                <AddressBar />
            </div>
            <RegistryBrowser />
            <AgentDetail />
        </div>
    }
}
