use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::{builtin_model_catalog, ModelAvailability, OrchestratorConfig, OrchestratorStatus, SetupState};

#[component]
pub fn SetupWizard() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let show_wizard = RwSignal::new(false);
    let wizard_error = RwSignal::new(None::<String>);
    let selected_provider = RwSignal::new("builtin".to_string());
    let builtin_model = RwSignal::new("tinyllama-1.1b".to_string());
    let builtin_models = RwSignal::new(builtin_model_catalog());
    let ollama_endpoint = RwSignal::new("http://localhost:11434".to_string());
    let ollama_model = RwSignal::new("llama3.2:1b".to_string());
    let openai_endpoint = RwSignal::new(String::new());
    let openai_key = RwSignal::new(String::new());
    let openai_model = RwSignal::new(String::new());
    let model_availability = RwSignal::new(Vec::<ModelAvailability>::new());
    let downloading = RwSignal::new(false);

    // Check setup state on mount
    Effect::new(move || {
        let setup = orchestrator.setup_state;
        if setup.get().is_none() && bridge::tauri_available() {
            spawn_local(async move {
                match bridge::invoke_no_args::<SetupState>("get_setup_state").await {
                    Ok(state) => {
                        let should_show = !state.setup_complete || !state.llm_configured;
                        setup.set(Some(state));
                        if should_show {
                            show_wizard.set(true);
                        }
                    }
                    Err(e) => {
                        web_sys::console::error_1(&format!("get_setup_state: {e}").into());
                    }
                }
            });
        }
    });

    Effect::new(move || {
        if !bridge::tauri_available() { return; }
        spawn_local(async move {
            if let Ok(avail) = bridge::invoke_no_args::<Vec<ModelAvailability>>(
                "check_model_availability"
            ).await {
                model_availability.set(avail);
            }
        });
    });

    let save_config = move |_| {
        let provider = selected_provider.get();
        let llm = match provider.as_str() {
            "builtin" => papillon_shared::LlmProvider::BuiltIn {
                model_id: builtin_model.get(),
            },
            "ollama" => papillon_shared::LlmProvider::Ollama {
                endpoint: ollama_endpoint.get(),
                model: ollama_model.get(),
            },
            "openai" => papillon_shared::LlmProvider::OpenAiCompatible {
                endpoint: openai_endpoint.get(),
                api_key: openai_key.get(),
                model: openai_model.get(),
            },
            _ => papillon_shared::LlmProvider::None,
        };

        let config = OrchestratorConfig {
            llm_provider: llm,
            mandate_ttl_hours: 8,
            auto_approve_zero_disclosure: true,
        };

        spawn_local(async move {
            wizard_error.set(None);
            match bridge::invoke::<serde_json::Value, OrchestratorConfig>(
                "configure_orchestrator",
                &serde_json::json!({ "config": config }),
            )
            .await
            {
                Ok(saved) => {
                    orchestrator.config.set(saved);
                    // Refresh sidebar status (model is now loaded if BuiltIn)
                    if let Ok(status) =
                        bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status")
                            .await
                    {
                        orchestrator.status.set(status);
                    }
                    show_wizard.set(false);
                }
                Err(e) => {
                    let msg = if e.contains("model not found") || e.contains("Tokenizer not found") {
                        "Model files not downloaded. Use the Download button above first.".to_string()
                    } else {
                        "Could not save \u{2014} backend unavailable.".to_string()
                    };
                    wizard_error.set(Some(msg));
                }
            }
        });
    };

    let skip = move |_| {
        show_wizard.set(false);
    };

    view! {
        <Show when=move || show_wizard.get()>
            <div class="setup-overlay">
                <div class="setup-wizard">
                    <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 4px;">"Welcome to Papillon"</h2>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">
                        "Choose how the orchestrator runs inference. The built-in model runs entirely on your device \u{2014} no network calls, no data leaks."
                    </p>

                    <div class="setup-options">
                        <div
                            class=move || if selected_provider.get() == "builtin" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("builtin".into())
                        >
                            <div class="setup-option-title">"Built-in (Recommended)"</div>
                            <div class="setup-option-desc">"On-device TinyLlama via Candle \u{2014} downloads once, runs fully offline"</div>
                        </div>
                        <div
                            class=move || if selected_provider.get() == "ollama" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("ollama".into())
                        >
                            <div class="setup-option-title">"Ollama (requires HTTP)"</div>
                            <div class="setup-option-desc">"External process \u{2014} prompts leave this app via localhost"</div>
                        </div>
                        <div
                            class=move || if selected_provider.get() == "openai" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("openai".into())
                        >
                            <div class="setup-option-title">"OpenAI-compatible (requires network)"</div>
                            <div class="setup-option-desc">"Remote API \u{2014} prompts sent over the internet"</div>
                        </div>
                        <div
                            class=move || if selected_provider.get() == "none" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("none".into())
                        >
                            <div class="setup-option-title">"Skip for now"</div>
                            <div class="setup-option-desc">"Search and knowledge agents only, no AI"</div>
                        </div>
                    </div>

                    // Built-in model picker
                    <Show when=move || selected_provider.get() == "builtin">
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
                            {move || {
                                let mid = builtin_model.get();
                                let avail = model_availability.get();
                                let is_ready = avail.iter().any(|a| a.model_id == mid && a.ready);

                                if !bridge::tauri_available() {
                                    view! {
                                        <div style="background: rgba(108, 92, 231, 0.08); border: 1px solid rgba(108, 92, 231, 0.3); border-radius: 6px; padding: 10px 12px; margin-top: 8px;">
                                            <p style="font-size: 12px; font-weight: 600; color: #6c5ce7; margin-bottom: 4px;">
                                                "Browser extension required"
                                            </p>
                                            <p style="font-size: 12px; color: var(--text-secondary);">
                                                "On-device inference requires the Papillon desktop app. "
                                                "Install the browser extension to connect pap:// URLs to your local instance."
                                            </p>
                                        </div>
                                    }.into_any()
                                } else if is_ready {
                                    view! {
                                        <p style="font-size: 11px; color: #00b894; margin-top: 4px;">
                                            "Model ready. Runs entirely on-device \u{2014} no network calls."
                                        </p>
                                    }.into_any()
                                } else {
                                    view! {
                                        <div style="margin-top: 8px;">
                                            <p style="font-size: 11px; color: #fdcb6e; margin-bottom: 8px;">
                                                "Model download required (~0.6 GB). One-time download, then fully offline."
                                            </p>
                                            <Show when=move || !downloading.get()>
                                                <button
                                                    class="btn btn-primary"
                                                    style="font-size: 12px; padding: 6px 16px;"
                                                    on:click=move |_| {
                                                        let mid = builtin_model.get();
                                                        downloading.set(true);
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
                                                                    wizard_error.set(Some(format!("Download failed: {e}")));
                                                                }
                                                            }
                                                            downloading.set(false);
                                                        });
                                                    }
                                                >"Download Model"</button>
                                            </Show>
                                            <Show when=move || downloading.get()>
                                                <p style="font-size: 11px; color: var(--text-secondary);">
                                                    "Downloading model files..."
                                                </p>
                                            </Show>
                                        </div>
                                    }.into_any()
                                }
                            }}
                        </div>
                    </Show>

                    // Security warning for HTTP providers
                    <Show when=move || selected_provider.get() == "ollama" || selected_provider.get() == "openai">
                        <div style="background: rgba(255, 107, 107, 0.08); border: 1px solid rgba(255, 107, 107, 0.3); border-radius: 6px; padding: 10px 12px; margin-top: 12px;">
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

                    // Conditional config inputs
                    <Show when=move || selected_provider.get() == "ollama">
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

                    <Show when=move || selected_provider.get() == "openai">
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

                    <Show when=move || wizard_error.get().is_some()>
                        <p style="color: var(--error); font-size: 12px; margin-top: 12px;">
                            {move || wizard_error.get().unwrap_or_default()}
                        </p>
                    </Show>

                    <div style="display: flex; gap: 12px; margin-top: 20px; justify-content: flex-end;">
                        <button class="btn" style="background: var(--bg-tertiary); color: var(--text-secondary);" on:click=skip>
                            "Skip"
                        </button>
                        <button class="btn btn-primary" on:click=save_config>
                            "Save"
                        </button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
