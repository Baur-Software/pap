use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::address_bar::AddressBar;
use crate::components::profile_avatar::ProfileAvatar;
use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;

mod templates_tab;
use templates_tab::TemplatesTab;
use papillion_shared::{
    builtin_model_catalog, ExportedKey, KeyBackupStatus, LlmProvider, OrchestratorConfig,
    OrchestratorStatus, ProfileMetadata, SuccessorDesignation,
};

#[component]
pub fn SettingsPage() -> impl IntoView {
    let active_tab = RwSignal::new("general".to_string());

    view! {
        <div class="page">
            <h2 class="page-title">"Settings"</h2>
            <div class="settings-tabs">
                <button
                    class=move || if active_tab.get() == "general" { "settings-tab active" } else { "settings-tab" }
                    on:click=move |_| active_tab.set("general".into())
                >"General"</button>
                <button
                    class=move || if active_tab.get() == "profiles" { "settings-tab active" } else { "settings-tab" }
                    on:click=move |_| active_tab.set("profiles".into())
                >"Profiles"</button>
                <button
                    class=move || if active_tab.get() == "templates" { "settings-tab active" } else { "settings-tab" }
                    on:click=move |_| active_tab.set("templates".into())
                >"Templates"</button>
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
            <Show when=move || active_tab.get() == "profiles">
                <ProfilesTab />
            </Show>
            <Show when=move || active_tab.get() == "templates">
                <TemplatesTab />
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
    let selected = RwSignal::new("builtin".to_string());
    let builtin_model = RwSignal::new("tinyllama-1.1b".to_string());
    let builtin_models = RwSignal::new(builtin_model_catalog());
    let mistral_key = RwSignal::new(String::new());
    let mistral_model = RwSignal::new("mistral-small-latest".to_string());
    let ollama_endpoint = RwSignal::new("http://localhost:11434".to_string());
    let ollama_model = RwSignal::new("llama3.2:1b".to_string());
    let openai_endpoint = RwSignal::new(String::new());
    let openai_key = RwSignal::new(String::new());
    let openai_model = RwSignal::new(String::new());
    let saved_msg = RwSignal::new(false);
    let save_error = RwSignal::new(None::<String>);

    // Initialize from current config
    Effect::new(move || {
        let config = orchestrator.config.get();
        match &config.llm_provider {
            LlmProvider::BuiltIn { model_id } => {
                selected.set("builtin".into());
                builtin_model.set(model_id.clone());
            }
            LlmProvider::Mistral { api_key, model } => {
                selected.set("mistral".into());
                mistral_key.set(api_key.clone());
                mistral_model.set(model.clone());
            }
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
            "builtin" => LlmProvider::BuiltIn {
                model_id: builtin_model.get(),
            },
            "mistral" => LlmProvider::Mistral {
                api_key: mistral_key.get(),
                model: mistral_model.get(),
            },
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
            save_error.set(None);
            saved_msg.set(false);
            match bridge::invoke::<serde_json::Value, OrchestratorConfig>(
                "configure_orchestrator",
                &serde_json::json!({ "config": config }),
            )
            .await
            {
                Ok(saved_config) => {
                    orchestrator.config.set(saved_config);
                    saved_msg.set(true);
                    // Refresh sidebar status (model is now loaded if BuiltIn)
                    if let Ok(status) =
                        bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status")
                            .await
                    {
                        orchestrator.status.set(status);
                    }
                }
                Err(e) => {
                    let msg = if e.contains("Tauri IPC") {
                        "Could not save settings \u{2014} backend unavailable.".to_string()
                    } else if e.contains("Bundled model not found") {
                        "Built-in model file not found. Place the GGUF in the models/ directory."
                            .to_string()
                    } else {
                        format!("Save failed: {e}")
                    };
                    save_error.set(Some(msg));
                }
            }
        });
    };

    view! {
        <div class="card">
            <h3 style="font-size: 14px; margin-bottom: 12px;">"LLM Provider"</h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 16px;">
                "Configure the language model that powers the orchestrator. "
                "The built-in option runs entirely on-device with no network calls."
            </p>
            <select
                style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; color: var(--text-primary); font-size: 13px; margin-bottom: 16px;"
                on:change=move |ev| selected.set(event_target_value(&ev))
                prop:value=move || selected.get()
            >
                <option value="builtin">"Built-in (Recommended)"</option>
                <option value="mistral">"Mistral API"</option>
                <option value="ollama">"Ollama (requires HTTP)"</option>
                <option value="openai">"OpenAI-compatible (requires network)"</option>
                <option value="none">"None"</option>
            </select>

            // Built-in model picker
            <Show when=move || selected.get() == "builtin">
                <div class="setup-inputs">
                    <label>"Model"</label>
                    <select
                        style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; color: var(--text-primary); font-size: 13px;"
                        on:change=move |ev| builtin_model.set(event_target_value(&ev))
                        prop:value=move || builtin_model.get()
                    >
                        <For
                            each=move || builtin_models.get()
                            key=|m| m.id.clone()
                            children=move |model| {
                                view! {
                                    <option value={model.id.clone()}>
                                        {format!("{} ({})", model.display_name, model.size_hint)}
                                    </option>
                                }
                            }
                        />
                    </select>
                    <p style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                        "Ships with the app. Runs entirely on-device \u{2014} no network calls."
                    </p>
                </div>
            </Show>

            // Security warning for HTTP-based providers
            <Show when=move || selected.get() == "mistral" || selected.get() == "ollama" || selected.get() == "openai">
                <div style="background: rgba(255, 107, 107, 0.08); border: 1px solid rgba(255, 107, 107, 0.3); border-radius: 6px; padding: 10px 12px; margin-bottom: 12px;">
                    <p style="font-size: 12px; font-weight: 600; color: var(--error); margin-bottom: 4px;">
                        "Security disclosure"
                    </p>
                    <p style="font-size: 12px; color: var(--text-secondary);">
                        "The orchestrator has full context over your tokens, keys, and agent actions. "
                        "Sending prompts to an external API discloses this context to the provider. "
                        "PAP can still wrap these HTTP calls, but zero-trust guarantees no longer hold."
                    </p>
                </div>
            </Show>

            <Show when=move || selected.get() == "mistral">
                <div class="setup-inputs">
                    <label>"API Key"</label>
                    <input
                        type="password"
                        placeholder="your Mistral API key"
                        prop:value=move || mistral_key.get()
                        on:input=move |ev| mistral_key.set(event_target_value(&ev))
                    />
                    <label>"Model"</label>
                    <input
                        type="text"
                        prop:value=move || mistral_model.get()
                        on:input=move |ev| mistral_model.set(event_target_value(&ev))
                    />
                    <p style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                        "Get an API key at console.mistral.ai. Models: mistral-small-latest, mistral-large-latest"
                    </p>
                </div>
            </Show>

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
                <Show when=move || save_error.get().is_some()>
                    <span style="font-size: 12px; color: var(--error);">
                        {move || save_error.get().unwrap_or_default()}
                    </span>
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
    let export_error = RwSignal::new(None::<String>);
    let show_import = RwSignal::new(false);
    let import_input = RwSignal::new(String::new());
    let import_error = RwSignal::new(None::<String>);
    let show_add_successor = RwSignal::new(false);
    let successor_error = RwSignal::new(None::<String>);
    let succ_did = RwSignal::new(String::new());
    let succ_rel = RwSignal::new("executor".to_string());
    let succ_notes = RwSignal::new(String::new());

    // Load backup status + successors on mount
    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
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
            export_error.set(None);
            match bridge::invoke_no_args::<ExportedKey>("export_key").await {
                Ok(key) => {
                    exported_key.set(Some(key.seed_b64));
                    identity.backed_up.set(true);
                    show_export.set(true);
                }
                Err(_) => {
                    export_error.set(Some(
                        "Could not export key \u{2014} backend unavailable.".into(),
                    ));
                }
            }
        });
    };

    let handle_import = move |_| {
        let seed = import_input.get();
        spawn_local(async move {
            import_error.set(None);
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
                }
                Err(e) => {
                    let msg = if e.contains("Tauri IPC") {
                        "Could not import key \u{2014} backend unavailable.".to_string()
                    } else {
                        format!("Import failed: {e}")
                    };
                    import_error.set(Some(msg));
                }
            }
        });
    };

    let handle_add_successor = move |_| {
        let did = succ_did.get();
        let rel = succ_rel.get();
        let notes = succ_notes.get();
        spawn_local(async move {
            successor_error.set(None);
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
                Err(_) => {
                    successor_error.set(Some(
                        "Could not add successor \u{2014} backend unavailable.".into(),
                    ));
                }
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
                fallback=move || view! {
                    <p style="color: var(--text-secondary);">
                        {move || if identity.loading.get() {
                            "Loading identity\u{2026}"
                        } else {
                            "No identity loaded. Create one by exporting a key, or import an existing key."
                        }}
                    </p>
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
            <Show when=move || export_error.get().is_some()>
                <p style="color: var(--error); font-size: 12px; margin-top: 8px;">
                    {move || export_error.get().unwrap_or_default()}
                </p>
            </Show>
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
                children=move |successor| {
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
                                        successor_error.set(None);
                                        match bridge::invoke::<serde_json::Value, Vec<SuccessorDesignation>>(
                                            "remove_successor",
                                            &serde_json::json!({ "successorDid": did }),
                                        ).await {
                                            Ok(suc) => identity.successors.set(suc),
                                            Err(_) => {
                                                successor_error.set(Some("Could not remove successor \u{2014} backend unavailable.".into()));
                                            }
                                        }
                                    });
                                }
                            >"Remove"</button>
                        </div>
                    }
                }
            />

            <Show when=move || successor_error.get().is_some()>
                <p style="color: var(--error); font-size: 12px; margin-top: 8px;">
                    {move || successor_error.get().unwrap_or_default()}
                </p>
            </Show>

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
            <ThisNodeCard />
            <SavedRegistriesCard />
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

#[component]
fn ThisNodeCard() -> impl IntoView {
    let node_did = RwSignal::new(String::new());
    let node_fingerprint = RwSignal::new(String::new());
    let node_addresses = RwSignal::new(Vec::<String>::new());
    let copied = RwSignal::new(None::<String>);

    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        spawn_local(async move {
            if let Ok(info) = bridge::invoke_no_args::<serde_json::Value>("get_node_info").await {
                if let Some(did) = info.get("did").and_then(|v| v.as_str()) {
                    node_did.set(did.to_string());
                }
                if let Some(fp) = info.get("cert_fingerprint").and_then(|v| v.as_str()) {
                    node_fingerprint.set(fp.to_string());
                }
            }
            if let Ok(addrs) = bridge::invoke_no_args::<Vec<String>>("get_node_addresses").await {
                node_addresses.set(addrs);
            }
        });
    });

    let copy_to_clipboard = move |text: String| {
        let text_clone = text.clone();
        // If the same item is already showing "Copied!", toggle it off
        if copied.get().as_deref() == Some(&text) {
            copied.set(None);
            return;
        }
        spawn_local(async move {
            let promise = web_sys::window()
                .map(|w| w.navigator().clipboard())
                .map(|c| c.write_text(&text_clone));
            if let Some(p) = promise {
                let _ = wasm_bindgen_futures::JsFuture::from(p).await;
            }
            copied.set(Some(text_clone));
        });
    };

    view! {
        <div class="card" style="margin-bottom: 16px;">
            <h3 style="font-size: 14px; margin-bottom: 4px;">"This Node"</h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                "Share a URL below with other devices on your LAN to let them connect to this node."
            </p>

            // LAN addresses
            <Show
                when=move || !node_addresses.get().is_empty()
                fallback=move || view! {
                    <p style="font-size: 12px; color: var(--text-secondary);">
                        "No LAN addresses detected \u{2014} federation server may still be starting."
                    </p>
                }
            >
                <div style="margin-bottom: 12px;">
                    <span style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 4px;">"LAN addresses"</span>
                    <For
                        each=move || node_addresses.get()
                        key=|addr| addr.clone()
                        children=move |addr| {
                            let addr_copy = addr.clone();
                            let addr_display = addr.clone();
                            let is_copied = {
                                let addr_check = addr.clone();
                                move || copied.get().as_deref() == Some(&addr_check)
                            };
                            view! {
                                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                                    <code style="font-size: 12px; background: var(--bg-tertiary); padding: 4px 8px; border-radius: 4px; flex: 1; word-break: break-all; font-family: 'JetBrains Mono', monospace;">
                                        {addr_display}
                                    </code>
                                    <button
                                        class="btn"
                                        style="padding: 4px 10px; font-size: 11px; background: var(--bg-tertiary); color: var(--text-secondary); white-space: nowrap;"
                                        on:click=move |_| copy_to_clipboard(addr_copy.clone())
                                    >
                                        {move || if is_copied() { "Copied!" } else { "Copy" }}
                                    </button>
                                </div>
                            }
                        }
                    />
                </div>
            </Show>

            // Cert fingerprint
            <Show when=move || !node_fingerprint.get().is_empty()>
                <div style="margin-bottom: 8px;">
                    <span style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 4px;">"Certificate fingerprint (SHA-256)"</span>
                    <code style="font-size: 11px; word-break: break-all; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace;">
                        {move || node_fingerprint.get()}
                    </code>
                </div>
            </Show>

            // DID
            <Show when=move || !node_did.get().is_empty()>
                <div>
                    <span style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 4px;">"Node DID"</span>
                    <code style="font-size: 11px; word-break: break-all; color: var(--text-secondary); font-family: 'JetBrains Mono', monospace;">
                        {move || node_did.get()}
                    </code>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn SavedRegistriesCard() -> impl IntoView {
    use crate::state::registry::RegistryState;

    let registry = expect_context::<RegistryState>();
    let bookmarks = RwSignal::new(Vec::<String>::new());
    let add_url = RwSignal::new(String::new());
    let add_error = RwSignal::new(None::<String>);
    let add_loading = RwSignal::new(false);

    // Load bookmarks on mount
    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        spawn_local(async move {
            if let Ok(bm) = bridge::invoke_no_args::<Vec<String>>("list_bookmarks").await {
                bookmarks.set(bm);
            }
        });
    });

    let handle_connect = move |url: String| {
        let url_clone = url.clone();
        spawn_local(async move {
            registry.current_url.set(url_clone.clone());
            registry.loading.set(true);
            registry.error.set(None);
            match bridge::invoke::<serde_json::Value, papillion_shared::RegistryInfo>(
                "navigate_registry",
                &serde_json::json!({ "url": url_clone }),
            )
            .await
            {
                Ok(info) => {
                    registry.info.set(Some(info));
                    registry.loading.set(false);
                }
                Err(e) => {
                    let msg = if e.contains("Tauri IPC") {
                        "Backend unavailable.".to_string()
                    } else {
                        e
                    };
                    registry.error.set(Some(msg));
                    registry.loading.set(false);
                }
            }
        });
    };

    let handle_remove = move |url: String| {
        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, Vec<String>>(
                "remove_bookmark",
                &serde_json::json!({ "registryUrl": url }),
            )
            .await
            {
                Ok(updated) => bookmarks.set(updated),
                Err(_) => {}
            }
        });
    };

    let handle_add = move |_| {
        let url = add_url.get().trim().to_string();
        if url.is_empty() {
            add_error.set(Some("Enter a registry URL, e.g. pap://192.168.1.x:7890".into()));
            return;
        }
        add_error.set(None);
        add_loading.set(true);
        spawn_local(async move {
            // TOFU handshake first — verify the registry is reachable
            match bridge::invoke::<serde_json::Value, papillion_shared::RegistryInfo>(
                "navigate_registry",
                &serde_json::json!({ "url": url }),
            )
            .await
            {
                Ok(_) => {
                    // Reachable — save the bookmark
                    match bridge::invoke::<serde_json::Value, Vec<String>>(
                        "add_bookmark",
                        &serde_json::json!({ "registryUrl": url }),
                    )
                    .await
                    {
                        Ok(updated) => {
                            bookmarks.set(updated);
                            add_url.set(String::new());
                        }
                        Err(e) => add_error.set(Some(e)),
                    }
                }
                Err(e) => {
                    let msg = if e.contains("Tauri IPC") {
                        "Backend unavailable.".to_string()
                    } else {
                        format!("Could not connect: {e}")
                    };
                    add_error.set(Some(msg));
                }
            }
            add_loading.set(false);
        });
    };

    view! {
        <div class="card" style="margin-bottom: 16px;">
            <h3 style="font-size: 14px; margin-bottom: 4px;">"Saved Registries"</h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                "Registries saved here reconnect automatically on startup."
            </p>

            // Bookmark list
            <For
                each=move || bookmarks.get()
                key=|url| url.clone()
                children=move |url| {
                    let url_connect = url.clone();
                    let url_remove = url.clone();
                    let url_display = url.clone();
                    let is_local = url == "pap://local";
                    view! {
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px; padding: 8px; background: var(--bg-tertiary); border-radius: 6px;">
                            <code style="flex: 1; font-size: 12px; word-break: break-all; font-family: 'JetBrains Mono', monospace;">
                                {url_display}
                            </code>
                            <button
                                class="btn"
                                style="padding: 3px 10px; font-size: 11px; background: var(--bg-secondary); color: var(--text-primary); white-space: nowrap;"
                                on:click=move |_| handle_connect(url_connect.clone())
                            >
                                "Connect"
                            </button>
                            <button
                                class="btn"
                                style="padding: 3px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--error); white-space: nowrap;"
                                disabled=move || is_local
                                on:click=move |_| {
                                    if !is_local {
                                        handle_remove(url_remove.clone())
                                    }
                                }
                            >
                                "Remove"
                            </button>
                        </div>
                    }
                }
            />

            // Add registry form
            <div style="border-top: 1px solid var(--border); padding-top: 12px; margin-top: 4px;">
                <div style="display: flex; gap: 8px; align-items: flex-start;">
                    <input
                        type="text"
                        placeholder="pap://192.168.1.x:7890"
                        prop:value=move || add_url.get()
                        on:input=move |ev| add_url.set(event_target_value(&ev))
                        style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; color: var(--text-primary); font-size: 13px; font-family: 'JetBrains Mono', monospace;"
                    />
                    <button
                        class="btn btn-primary"
                        on:click=handle_add
                        disabled=move || add_loading.get()
                    >
                        {move || if add_loading.get() { "Connecting\u{2026}" } else { "Add" }}
                    </button>
                </div>
                <Show when=move || add_error.get().is_some()>
                    <p style="font-size: 12px; color: var(--error); margin-top: 6px;">
                        {move || add_error.get().unwrap_or_default()}
                    </p>
                </Show>
            </div>
        </div>
    }
}

#[component]
fn ProfilesTab() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let new_profile_name = RwSignal::new(String::new());
    let create_error = RwSignal::new(None::<String>);
    let create_success = RwSignal::new(false);
    let delete_confirm_profile_id = RwSignal::new(None::<String>);

    let create_profile = move |_| {
        let name = new_profile_name.get();
        if name.is_empty() {
            create_error.set(Some("Profile name cannot be empty".into()));
            return;
        }

        create_error.set(None);
        create_success.set(false);

        spawn_local(async move {
            match bridge::invoke::<_, ProfileMetadata>(
                "create_profile",
                &serde_json::json!({ "name": name }),
            )
            .await
            {
                Ok(_new_profile) => {
                    new_profile_name.set(String::new());
                    create_success.set(true);
                    // Reload profiles list
                    if let Ok(profiles) = bridge::invoke_no_args::<Vec<_>>("list_profiles").await {
                        identity.profiles.set(profiles);
                    }
                }
                Err(e) => {
                    create_error.set(Some(e));
                }
            }
        });
    };

    let delete_profile = move |profile_id: String| {
        spawn_local(async move {
            match bridge::invoke::<_, ()>(
                "delete_profile",
                &serde_json::json!({ "profile_id": profile_id }),
            )
            .await
            {
                Ok(_) => {
                    delete_confirm_profile_id.set(None);
                    // Reload profiles list
                    if let Ok(profiles) = bridge::invoke_no_args::<Vec<_>>("list_profiles").await {
                        identity.profiles.set(profiles);
                    }
                }
                Err(_) => {
                    delete_confirm_profile_id.set(None);
                }
            }
        });
    };

    view! {
        <div class="card" style="margin-bottom: 16px;">
            <h3 style="font-size: 14px; margin-bottom: 12px;">"Manage Profiles"</h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 16px;">
                "Each profile has its own identity and workspace. Switch between them anytime."
            </p>

            // Profile list
            <div style="margin-bottom: 20px;">
                <For
                    each=move || identity.profiles.get()
                    key=|p| p.id.clone()
                    children=move |profile| {
                        let profile_id_for_delete = profile.id.clone();
                        let is_active = profile.active;
                        let profile_name = profile.name.clone();
                        let created = profile.created_at.clone();
                        let last_used = profile.last_used.clone();

                        view! {
                            <div style="display: flex; align-items: center; gap: 12px; padding: 12px; background: var(--bg-tertiary); border-radius: 6px; margin-bottom: 8px;">
                                <ProfileAvatar name=profile_name.clone() />
                                <div style="flex: 1; min-width: 0;">
                                    <div style="font-size: 13px; font-weight: 500;">{profile_name.clone()}</div>
                                    <div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px;">
                                        "Created " {created} {if let Some(lu) = &last_used { format!(" • Last used {}", lu) } else { "".into() }}
                                    </div>
                                </div>
                                <Show when=move || is_active>
                                    <span style="font-size: 11px; background: var(--teal); color: white; padding: 2px 8px; border-radius: 4px;">
                                        "✓ Active"
                                    </span>
                                </Show>
                                <button
                                    class="btn"
                                    style="padding: 4px 8px; font-size: 11px; background: var(--bg-secondary); color: var(--error);"
                                    on:click=move |_| {
                                        if !is_active {
                                            delete_confirm_profile_id.set(Some(profile_id_for_delete.clone()));
                                        }
                                    }
                                    disabled=move || is_active
                                >
                                    "Delete"
                                </button>
                            </div>
                        }
                    }
                />
            </div>

            // Create new profile
            <div style="border-top: 1px solid var(--border); padding-top: 16px;">
                <h4 style="font-size: 12px; font-weight: 600; margin-bottom: 8px;">"Create Profile"</h4>
                <div style="display: flex; gap: 8px;">
                    <input
                        type="text"
                        placeholder="Profile name (e.g., Work, Personal)"
                        prop:value=move || new_profile_name.get()
                        on:input=move |ev| new_profile_name.set(event_target_value(&ev))
                        style="flex: 1; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; color: var(--text-primary); font-size: 13px;"
                    />
                    <button class="btn btn-primary" on:click=create_profile>
                        "Create"
                    </button>
                </div>
                <Show when=move || create_error.get().is_some()>
                    <div style="font-size: 12px; color: var(--error); margin-top: 8px;">
                        {move || create_error.get().unwrap_or_default()}
                    </div>
                </Show>
                <Show when=move || create_success.get()>
                    <div style="font-size: 12px; color: var(--success); margin-top: 8px;">
                        "Profile created!"
                    </div>
                </Show>
            </div>
        </div>

        // Delete confirmation dialog
        <Show when=move || delete_confirm_profile_id.get().is_some()>
            {
                let profile_id = delete_confirm_profile_id.get().unwrap_or_default();
                let profile_name = identity.profiles.get()
                    .iter()
                    .find(|p| p.id == profile_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Unknown".into());

                view! {
                    <div style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0, 0, 0, 0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;">
                        <div style="background: var(--bg-primary); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 400px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);">
                            <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">
                                "Delete Profile?"
                            </h3>
                            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">
                                "Are you sure you want to delete \"" {profile_name.clone()} "\"? This cannot be undone. Episodes tied to this profile won't be deleted."
                            </p>
                            <div style="display: flex; gap: 8px; justify-content: flex-end;">
                                <button
                                    class="btn"
                                    on:click=move |_| delete_confirm_profile_id.set(None)
                                    style="background: var(--bg-tertiary);"
                                >
                                    "Cancel"
                                </button>
                                <button
                                    class="btn"
                                    on:click=move |_| delete_profile(profile_id.clone())
                                    style="background: var(--error); color: white;"
                                >
                                    "Delete Profile"
                                </button>
                            </div>
                        </div>
                    </div>
                }
            }
        </Show>
    }
}
