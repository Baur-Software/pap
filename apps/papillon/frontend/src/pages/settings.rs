use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::address_bar::AddressBar;
use crate::components::profile_avatar::ProfileAvatar;
use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;

mod templates_tab;
use papillon_shared::{
    builtin_model_catalog, ExportedKey, KeyBackupStatus, LlmProvider, ModelAvailability,
    OrchestratorConfig, OrchestratorStatus, ProfileMetadata, SuccessorDesignation,
};
use templates_tab::TemplatesTab;

#[component]
pub fn SettingsPage() -> impl IntoView {
    let active_tab = RwSignal::new("profiles".to_string());

    view! {
        <div class="settings-page settings-layout">

            // ── Left nav ──
            <nav class="settings-nav">

                <div class="settings-nav-group-label">"Account"</div>
                <button
                    class=move || if active_tab.get() == "profiles" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("profiles".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    </span>
                    "Profiles"
                </button>
                <button
                    class=move || if active_tab.get() == "identity" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("identity".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    </span>
                    "Identity"
                </button>

                <div class="settings-nav-divider" />
                <div class="settings-nav-group-label">"AI"</div>
                <button
                    class=move || if active_tab.get() == "model" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("model".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
                    </span>
                    "Model"
                </button>
                <button
                    class=move || if active_tab.get() == "templates" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("templates".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    </span>
                    "Templates"
                </button>

                <div class="settings-nav-divider" />
                <div class="settings-nav-group-label">"Security"</div>
                <button
                    class=move || if active_tab.get() == "access-control" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("access-control".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    </span>
                    "Access Control"
                </button>
                <button
                    class=move || if active_tab.get() == "advanced" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("advanced".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
                    </span>
                    "Advanced"
                </button>

                <div class="settings-nav-divider" />
                <div class="settings-nav-group-label">"Appearance"</div>
                <button
                    class=move || if active_tab.get() == "appearance" { "settings-nav-link active" } else { "settings-nav-link" }
                    on:click=move |_| active_tab.set("appearance".into())
                >
                    <span class="settings-nav-icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
                    </span>
                    "Appearance"
                </button>

            </nav>

            // ── Content ──
            <div class="settings-content">
                <Show when=move || active_tab.get() == "profiles">
                    <ProfilesTab />
                </Show>
                <Show when=move || active_tab.get() == "identity">
                    <IdentityTab />
                </Show>
                <Show when=move || active_tab.get() == "model">
                    <GeneralTab />
                </Show>
                <Show when=move || active_tab.get() == "templates">
                    <TemplatesTab />
                </Show>
                <Show when=move || active_tab.get() == "access-control">
                    <MandateBuilderTab />
                </Show>
                <Show when=move || active_tab.get() == "advanced">
                    <AdvancedTab />
                </Show>
                <Show when=move || active_tab.get() == "appearance">
                    <AppearanceTab />
                </Show>
            </div>

        </div>
    }
}

#[component]
fn GeneralTab() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let selected = RwSignal::new("builtin".to_string());
    let builtin_model = RwSignal::new("gemma-4-e2b".to_string());
    let builtin_models = RwSignal::new(builtin_model_catalog());
    let mistral_key = RwSignal::new(String::new());
    let mistral_model = RwSignal::new("mistral-small-latest".to_string());
    let ollama_endpoint = RwSignal::new("http://localhost:11434".to_string());
    let ollama_model = RwSignal::new("mistral:latest".to_string());
    let openai_endpoint = RwSignal::new(String::new());
    let openai_key = RwSignal::new(String::new());
    let openai_model = RwSignal::new(String::new());
    let hf_token = RwSignal::new(String::new());
    let hf_model = RwSignal::new("google/gemma-4-E2B-it".to_string());
    let saved_msg = RwSignal::new(false);
    let save_error = RwSignal::new(None::<String>);
    let model_availability = RwSignal::new(Vec::<ModelAvailability>::new());
    let downloading = RwSignal::new(false);
    let download_progress = RwSignal::new(0u8);

    // Initialize from current config
    Effect::new(move || {
        let config = orchestrator.config.get();
        match &config.inference_substrate {
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
            LlmProvider::HuggingFace { api_token, model } => {
                selected.set("huggingface".into());
                hf_token.set(api_token.clone());
                hf_model.set(model.clone());
            }
            LlmProvider::None => selected.set("none".into()),
        }
    });

    // Check model availability on mount
    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        spawn_local(async move {
            if let Ok(avail) =
                bridge::invoke_no_args::<Vec<ModelAvailability>>("check_model_availability").await
            {
                model_availability.set(avail);
            }
        });
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
            "huggingface" => LlmProvider::HuggingFace {
                api_token: hf_token.get(),
                model: hf_model.get(),
            },
            _ => LlmProvider::None,
        };

        let config = OrchestratorConfig {
            inference_substrate: provider,
            mandate_ttl_hours: orchestrator.config.get().mandate_ttl_hours,
            auto_approve_zero_disclosure: orchestrator.config.get().auto_approve_zero_disclosure,
            intent_confidence_threshold: orchestrator.config.get().intent_confidence_threshold,
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
                    } else if e.contains("model not found") || e.contains("Tokenizer not found") {
                        "Model files not downloaded. Use the Download button above first."
                            .to_string()
                    } else {
                        format!("Save failed: {e}")
                    };
                    save_error.set(Some(msg));
                }
            }
        });
    };

    let orch_status_text = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready | OrchestratorStatus::Unconfigured => "ACTIVE",
        OrchestratorStatus::Downloading { .. } => "LOADING",
        OrchestratorStatus::Disconnected => "OFFLINE",
    };
    let orch_status_color = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready | OrchestratorStatus::Unconfigured => "#00b894",
        OrchestratorStatus::Downloading { .. } => "#fdcb6e",
        OrchestratorStatus::Disconnected => "#b2bec3",
    };

    view! {
        <div class="card">
            // ── PAP Orchestrator ─────────────────────────────────────
            <div style="margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border);">
                <h3 style="font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 8px; font-family: var(--font-mono);">
                    "PAP_ORCHESTRATOR"
                </h3>
                <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
                    "Routes your intent to agents. Deterministic — never sends data to an external model."
                </p>
                <div style="display: flex; flex-direction: column; gap: 8px;">
                    <div style="display: flex; align-items: center; gap: 8px; font-size: 12px;">
                        <span style="color: var(--text-tertiary); font-family: var(--font-mono); font-size: 10px; min-width: 100px;">"STATUS"</span>
                        <span style=move || format!("color: {}; font-family: var(--font-mono); font-size: 11px;", orch_status_color())>{move || orch_status_text()}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px; font-size: 12px;">
                        <span style="color: var(--text-tertiary); font-family: var(--font-mono); font-size: 10px; min-width: 100px;">"MANDATE TTL"</span>
                        <span style="color: var(--text-primary); font-family: var(--font-mono); font-size: 11px;">"1h per execution (renewable, bounded)"</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px; font-size: 12px;">
                        <span style="color: var(--text-tertiary); font-family: var(--font-mono); font-size: 10px; min-width: 100px;">"AUTO-APPROVE"</span>
                        <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                            <input
                                type="checkbox"
                                prop:checked=move || orchestrator.config.get().auto_approve_zero_disclosure
                                on:change=move |ev| {
                                    use web_sys::HtmlInputElement;
                                    use wasm_bindgen::JsCast;
                                    let checked = ev.target()
                                        .and_then(|t| t.dyn_into::<HtmlInputElement>().ok())
                                        .map(|el| el.checked())
                                        .unwrap_or(false);
                                    let mut cfg = orchestrator.config.get();
                                    cfg.auto_approve_zero_disclosure = checked;
                                    let cfg_clone = cfg.clone();
                                    spawn_local(async move {
                                        let _ = bridge::invoke::<serde_json::Value, OrchestratorConfig>(
                                            "configure_orchestrator",
                                            &serde_json::json!({ "config": cfg_clone }),
                                        ).await;
                                    });
                                    orchestrator.config.set(cfg);
                                }
                            />
                            <span style="font-size: 11px; color: var(--text-secondary);">"Skip approval for zero-disclosure requests"</span>
                        </label>
                    </div>
                </div>
            </div>

            // ── Inference Substrate (optional) ────────────────────────
            <h3 style="font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 8px; font-family: var(--font-mono);">
                "INFERENCE_SUBSTRATE"
                <span style="font-size: 10px; color: var(--text-tertiary); margin-left: 8px; text-transform: none; letter-spacing: 0;">"optional"</span>
            </h3>
            <p style="font-size: 12px; color: var(--text-secondary); margin-bottom: 16px;">
                "Synthesizes natural-language answers from structured agent data. "
                "PAP routing works without it. Sending queries to an external provider "
                "shares your query context with that provider."
            </p>
            <select
                style="width: 100%; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; padding: 8px; color: var(--text-primary); font-size: 13px; margin-bottom: 16px;"
                on:change=move |ev| selected.set(event_target_value(&ev))
                prop:value=move || selected.get()
            >
                <option value="builtin">"Built-in (Recommended)"</option>
                <option value="mistral">"Mistral API"</option>
                <option value="ollama">"Ollama (local)"</option>
                <option value="huggingface">"HuggingFace Inference API"</option>
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

                    // Model availability status
                    {move || {
                        let mid = builtin_model.get();
                        let avail = model_availability.get();
                        let is_ready = avail.iter().any(|a| a.model_id == mid && a.ready);
                        let is_checking = avail.is_empty() && bridge::tauri_available();

                        if !bridge::tauri_available() {
                            // Browser context — suggest extension
                            view! {
                                <div style="background: rgba(108, 92, 231, 0.08); border: 1px solid rgba(108, 92, 231, 0.3); border-radius: 6px; padding: 10px 12px; margin-top: 8px;">
                                    <p style="font-size: 12px; font-weight: 600; color: var(--brand); margin-bottom: 4px;">
                                        "Browser extension required"
                                    </p>
                                    <p style="font-size: 12px; color: var(--text-secondary);">
                                        "On-device inference requires the Papillon desktop app. "
                                        "Install the browser extension to connect pap:// URLs to your local instance."
                                    </p>
                                </div>
                            }.into_any()
                        } else if is_checking {
                            view! {
                                <p style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                                    "Checking model availability..."
                                </p>
                            }.into_any()
                        } else if is_ready {
                            view! {
                                <p style="font-size: 11px; color: #00b894; margin-top: 4px;">
                                    "Model files present. Ready to use."
                                </p>
                            }.into_any()
                        } else {
                            view! {
                                <div style="margin-top: 8px;">
                                    <p style="font-size: 11px; color: #fdcb6e; margin-bottom: 8px;">
                                        "Model files not found. Download required (~0.6 GB)."
                                    </p>
                                    <Show when=move || !downloading.get()>
                                        <button
                                            class="btn btn-primary"
                                            style="font-size: 12px; padding: 6px 16px;"
                                            on:click=move |_| {
                                                let mid = builtin_model.get();
                                                downloading.set(true);
                                                download_progress.set(0);
                                                spawn_local(async move {
                                                    match bridge::invoke::<serde_json::Value, ModelAvailability>(
                                                        "download_builtin_model",
                                                        &serde_json::json!({ "modelId": mid }),
                                                    ).await {
                                                        Ok(avail) => {
                                                            model_availability.update(|list| {
                                                                if let Some(entry) = list.iter_mut().find(|m| m.model_id == avail.model_id) {
                                                                    *entry = avail;
                                                                } else {
                                                                    list.push(avail);
                                                                }
                                                            });
                                                        }
                                                        Err(e) => {
                                                            save_error.set(Some(format!("Download failed: {e}")));
                                                        }
                                                    }
                                                    downloading.set(false);
                                                });
                                            }
                                        >"Download Model"</button>
                                    </Show>
                                    <Show when=move || downloading.get()>
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <div style="flex: 1; height: 6px; background: var(--bg-tertiary); border-radius: 3px; overflow: hidden;">
                                                <div style=move || format!("width: {}%; height: 100%; background: var(--brand); border-radius: 3px; transition: width 0.3s;", download_progress.get())></div>
                                            </div>
                                            <span style="font-size: 11px; color: var(--text-secondary);">
                                                "Downloading..."
                                            </span>
                                        </div>
                                    </Show>
                                </div>
                            }.into_any()
                        }
                    }}
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

            <Show when=move || selected.get() == "huggingface">
                <div class="setup-inputs">
                    <label>"Access Token"</label>
                    <input
                        type="password"
                        placeholder="hf_..."
                        prop:value=move || hf_token.get()
                        on:input=move |ev| hf_token.set(event_target_value(&ev))
                    />
                    <label>"Model ID"</label>
                    <input
                        type="text"
                        placeholder="google/gemma-4-E2B-it"
                        prop:value=move || hf_model.get()
                        on:input=move |ev| hf_model.set(event_target_value(&ev))
                    />
                    <p style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                        "Get a free token at huggingface.co/settings/tokens. Enter any Hub model ID."
                    </p>
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
            <SessionInfoSection />
        </div>
    }
}

#[component]
fn SessionInfoSection() -> impl IntoView {
    use crate::state::canvas::CanvasState;
    let canvas_state = expect_context::<CanvasState>();
    let orchestrator = expect_context::<OrchestratorState>();
    let expanded = RwSignal::new(false);

    let session_id = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.id.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "NO_SESSION".to_string())
    };

    let block_count = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks.len())
            .unwrap_or(0)
    };

    let llm_status = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "SUBSTRATE_READY",
        OrchestratorStatus::Unconfigured => "NOT_CONFIGURED",
        OrchestratorStatus::Disconnected => "DISCONNECTED",
        _ => "UNKNOWN",
    };

    view! {
        <div class="settings-session-section">
            <button
                class="settings-session-toggle"
                on:click=move |_| expanded.update(|v| *v = !*v)
            >
                <span>"INTENT_MEMORY"</span>
                <span>{move || if expanded.get() { "▲" } else { "▼" }}</span>
            </button>
            <Show when=move || expanded.get()>
                <div class="settings-session-body">
                    <div class="intent-section">
                        <div class="intent-section-label">"SESSION"</div>
                        <div class="intent-kv">
                            <span class="intent-key">"ID"</span>
                            <span class="intent-val">{session_id}</span>
                        </div>
                        <div class="intent-kv">
                            <span class="intent-key">"BLOCKS"</span>
                            <span class="intent-val">{block_count}</span>
                        </div>
                    </div>
                    <div class="intent-divider" />
                    <div class="intent-section">
                        <div class="intent-section-label">"SUBSTRATE"</div>
                        <div class="intent-kv">
                            <span class="intent-key">"LLM"</span>
                            <span class="intent-val intent-val-status">{llm_status}</span>
                        </div>
                    </div>
                    <div class="intent-divider" />
                    <div class="intent-section">
                        <div class="intent-section-label">"SCOPE"</div>
                        <div class="intent-hint">"No active mandate"</div>
                        <div class="intent-hint">"Agents run zero-disclosure by default"</div>
                    </div>
                </div>
            </Show>
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
            match bridge::invoke::<serde_json::Value, papillon_shared::IdentityInfo>(
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
            match bridge::invoke::<serde_json::Value, papillon_shared::RegistryInfo>(
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
            if let Ok(updated) = bridge::invoke::<serde_json::Value, Vec<String>>(
                "remove_bookmark",
                &serde_json::json!({ "registryUrl": url }),
            )
            .await
            {
                bookmarks.set(updated);
            }
        });
    };

    let handle_add = move |_| {
        let url = add_url.get().trim().to_string();
        if url.is_empty() {
            add_error.set(Some(
                "Enter a registry URL, e.g. pap://192.168.1.x:7890".into(),
            ));
            return;
        }
        add_error.set(None);
        add_loading.set(true);
        spawn_local(async move {
            // TOFU handshake first — verify the registry is reachable
            match bridge::invoke::<serde_json::Value, papillon_shared::RegistryInfo>(
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

#[component]
fn MandateBuilderTab() -> impl IntoView {
    let scope_input = RwSignal::new(String::new());
    let ttl_hours = RwSignal::new(8u32);
    let auto_approve_zero = RwSignal::new(true);
    let principal_did = RwSignal::new(String::new());

    let preview_json = move || {
        let scope: Vec<String> = scope_input
            .get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "@context": "https://schema.org",
            "@type": "Mandate",
            "scope": scope,
            "ttl_hours": ttl_hours.get(),
            "auto_approve_zero_disclosure": auto_approve_zero.get(),
            "principal": if principal_did.get().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(principal_did.get())
            }
        }))
        .unwrap_or_default()
    };

    view! {
        <div class="mandate-builder">
            <div class="mandate-form-col">
                <div class="mandate-section">
                    <div class="mandate-section-label">"SCOPE_OBJECTIVES"</div>
                    <div class="mandate-field">
                        <label class="mandate-field-label">"ACTION_TYPES"</label>
                        <input
                            class="mandate-input"
                            type="text"
                            placeholder="schema:SearchAction, schema:ReadAction"
                            prop:value=move || scope_input.get()
                            on:input=move |ev| scope_input.set(event_target_value(&ev))
                        />
                        <div class="mandate-field-hint">"Comma-separated Schema.org action types"</div>
                    </div>
                </div>

                <div class="mandate-section">
                    <div class="mandate-section-label">"CONSTRAINTS"</div>
                    <div class="mandate-field">
                        <label class="mandate-field-label">"TTL_HOURS"</label>
                        <input
                            class="mandate-input mandate-input-narrow"
                            type="number"
                            min="1"
                            max="720"
                            prop:value=move || ttl_hours.get().to_string()
                            on:input=move |ev| {
                                if let Ok(v) = event_target_value(&ev).parse::<u32>() {
                                    ttl_hours.set(v);
                                }
                            }
                        />
                    </div>
                    <div class="mandate-field">
                        <label class="mandate-field-label mandate-field-row">
                            <input
                                type="checkbox"
                                class="mandate-checkbox"
                                prop:checked=move || auto_approve_zero.get()
                                on:change=move |ev| {
                                    if let Some(input) = ev.target().and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok()) {
                                        auto_approve_zero.set(input.checked());
                                    }
                                }
                            />
                            "AUTO_APPROVE_ZERO_DISCLOSURE"
                        </label>
                        <div class="mandate-field-hint">"Allow agents to run without requesting any personal data"</div>
                    </div>
                </div>

                <div class="mandate-section">
                    <div class="mandate-section-label">"DELEGATION_TARGET"</div>
                    <div class="mandate-field">
                        <label class="mandate-field-label">"PRINCIPAL_DID"</label>
                        <input
                            class="mandate-input"
                            type="text"
                            placeholder="did:key:z6Mk..."
                            prop:value=move || principal_did.get()
                            on:input=move |ev| principal_did.set(event_target_value(&ev))
                        />
                        <div class="mandate-field-hint">"Leave empty for self-mandate"</div>
                    </div>
                </div>
            </div>

            <div class="mandate-preview-col">
                <div class="mandate-section-label">"MANDATE_PREVIEW"</div>
                <pre class="mandate-preview-code">{preview_json}</pre>
                <div class="mandate-preview-note">
                    "Mandates are co-signed by the principal and scoped by TTL. "
                    "This preview shows the unsigned structure."
                </div>
            </div>
        </div>
    }
}

#[component]
fn AppearanceTab() -> impl IntoView {
    // Read initial values from localStorage / current data-theme
    let stored_theme = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_theme").ok().flatten())
        .unwrap_or_else(|| "dark".to_string());

    let stored_accent = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_accent").ok().flatten())
        .unwrap_or_else(|| "#6c5ce7".to_string());

    let stored_font_size = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_font_size").ok().flatten())
        .unwrap_or_else(|| "medium".to_string());

    let stored_reduce_motion = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_reduce_motion").ok().flatten())
        .map(|v| v == "true")
        .unwrap_or(false);

    let stored_compact = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("papillon_compact").ok().flatten())
        .map(|v| v == "true")
        .unwrap_or(false);

    let theme         = RwSignal::new(stored_theme);
    let accent        = RwSignal::new(stored_accent);
    let font_size     = RwSignal::new(stored_font_size);
    let reduce_motion = RwSignal::new(stored_reduce_motion);
    let compact       = RwSignal::new(stored_compact);

    // Helpers
    let apply_theme = move |t: &'static str| {
        theme.set(t.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element().map(|el| el.set_attribute("data-theme", t));
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_theme", t);
            }
        }
    };

    let apply_accent = move |color: &'static str| {
        accent.set(color.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let style = doc.document_element()
                    .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
                    .map(|el| el.style());
                if let Some(style) = style {
                    let _ = style.set_property("--purple", color);
                }
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_accent", color);
            }
        }
    };

    let apply_font_size = move |size: &'static str| {
        let scale = match size { "small" => "0.9", "large" => "1.1", _ => "1.0" };
        font_size.set(size.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let style = doc.document_element()
                    .and_then(|el| el.dyn_into::<web_sys::HtmlElement>().ok())
                    .map(|el| el.style());
                if let Some(style) = style {
                    let _ = style.set_property("--font-scale", scale);
                }
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_font_size", size);
            }
        }
    };

    let toggle_reduce_motion = move |_| {
        let next = !reduce_motion.get_untracked();
        reduce_motion.set(next);
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element()
                    .map(|el| el.set_attribute("data-reduce-motion", if next { "true" } else { "false" }));
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_reduce_motion", if next { "true" } else { "false" });
            }
        }
    };

    let toggle_compact = move |_| {
        let next = !compact.get_untracked();
        compact.set(next);
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element()
                    .map(|el| el.set_attribute("data-compact", if next { "true" } else { "false" }));
            }
            if let Ok(Some(s)) = win.local_storage() {
                let _ = s.set_item("papillon_compact", if next { "true" } else { "false" });
            }
        }
    };

    view! {
        <div class="settings-section-title">"Appearance"</div>
        <p class="settings-section-desc">"Customize how Papillon looks. Changes apply immediately."</p>

        <div class="settings-group">
            // Theme
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Theme"</strong>
                    <span>"Light or dark interface, or follow your system preference"</span>
                </div>
                <div class="settings-row-control">
                    <div class="appearance-theme-pills">
                        <button
                            class=move || if theme.get() == "light" { "appearance-theme-pill active" } else { "appearance-theme-pill" }
                            on:click=move |_| apply_theme("light")
                        >"Light"</button>
                        <button
                            class=move || if theme.get() == "dark" { "appearance-theme-pill active" } else { "appearance-theme-pill" }
                            on:click=move |_| apply_theme("dark")
                        >"Dark"</button>
                        <button
                            class=move || if theme.get() == "auto" { "appearance-theme-pill active" } else { "appearance-theme-pill" }
                            on:click=move |_| apply_theme("auto")
                        >"Auto"</button>
                    </div>
                </div>
            </div>

            // Accent color
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Accent color"</strong>
                    <span>"Used for active states, highlights, and interactive elements"</span>
                </div>
                <div class="settings-row-control">
                    <div class="appearance-swatches">
                        <button class=move || if accent.get() == "#6c5ce7" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#6c5ce7" title="Purple (default)" on:click=move |_| apply_accent("#6c5ce7") />
                        <button class=move || if accent.get() == "#00b894" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#00b894" title="Teal" on:click=move |_| apply_accent("#00b894") />
                        <button class=move || if accent.get() == "#e8706a" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#e8706a" title="Coral" on:click=move |_| apply_accent("#e8706a") />
                        <button class=move || if accent.get() == "#fdcb6e" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#fdcb6e" title="Gold" on:click=move |_| apply_accent("#fdcb6e") />
                        <button class=move || if accent.get() == "#74b9ff" { "appearance-swatch active" } else { "appearance-swatch" }
                            style="background:#74b9ff" title="Blue" on:click=move |_| apply_accent("#74b9ff") />
                    </div>
                </div>
            </div>

            // Font size
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Font size"</strong>
                    <span>"Base interface text size"</span>
                </div>
                <div class="settings-row-control">
                    <select
                        class="appearance-select"
                        on:change=move |e| {
                            let val = event_target_value(&e);
                            match val.as_str() {
                                "small" => apply_font_size("small"),
                                "large" => apply_font_size("large"),
                                _ => apply_font_size("medium"),
                            }
                        }
                        prop:value=move || font_size.get()
                    >
                        <option value="small">"Small"</option>
                        <option value="medium">"Medium"</option>
                        <option value="large">"Large"</option>
                    </select>
                </div>
            </div>
        </div>

        <div class="settings-group">
            // Reduce motion
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Reduce motion"</strong>
                    <span>"Disable slide and fade animations"</span>
                </div>
                <div class="settings-row-control">
                    <button
                        class=move || if reduce_motion.get() { "appearance-toggle on" } else { "appearance-toggle" }
                        on:click=toggle_reduce_motion
                        aria-label="Toggle reduce motion"
                    />
                </div>
            </div>

            // Compact density
            <div class="settings-row">
                <div class="settings-row-label">
                    <strong>"Compact density"</strong>
                    <span>"Tighter spacing throughout the interface"</span>
                </div>
                <div class="settings-row-control">
                    <button
                        class=move || if compact.get() { "appearance-toggle on" } else { "appearance-toggle" }
                        on:click=toggle_compact
                        aria-label="Toggle compact density"
                    />
                </div>
            </div>
        </div>
    }
}
