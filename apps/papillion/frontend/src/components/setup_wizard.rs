use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::{OrchestratorConfig, SetupState};

#[component]
pub fn SetupWizard() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let show_wizard = RwSignal::new(false);
    let selected_provider = RwSignal::new("none".to_string());
    let ollama_endpoint = RwSignal::new("http://localhost:11434".to_string());
    let ollama_model = RwSignal::new("llama3.2:1b".to_string());
    let openai_endpoint = RwSignal::new(String::new());
    let openai_key = RwSignal::new(String::new());
    let openai_model = RwSignal::new(String::new());

    // Check setup state on mount
    Effect::new(move || {
        let setup = orchestrator.setup_state;
        if setup.get().is_none() {
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
                        web_sys::console::error_1(
                            &format!("Failed to check setup state: {e}").into(),
                        );
                    }
                }
            });
        }
    });

    let save_config = move |_| {
        let provider = selected_provider.get();
        let llm = match provider.as_str() {
            "ollama" => papillion_shared::LlmProvider::Ollama {
                endpoint: ollama_endpoint.get(),
                model: ollama_model.get(),
            },
            "openai" => papillion_shared::LlmProvider::OpenAiCompatible {
                endpoint: openai_endpoint.get(),
                api_key: openai_key.get(),
                model: openai_model.get(),
            },
            _ => papillion_shared::LlmProvider::None,
        };

        let config = OrchestratorConfig {
            llm_provider: llm,
            mandate_ttl_hours: 8,
            auto_approve_zero_disclosure: true,
        };

        spawn_local(async move {
            match bridge::invoke::<serde_json::Value, OrchestratorConfig>(
                "configure_orchestrator",
                &serde_json::json!({ "config": config }),
            )
            .await
            {
                Ok(saved) => {
                    orchestrator.config.set(saved);
                    show_wizard.set(false);
                }
                Err(e) => {
                    web_sys::console::error_1(
                        &format!("Failed to save config: {e}").into(),
                    );
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
                    <h2 style="font-size: 18px; font-weight: 600; margin-bottom: 4px;">"Welcome to Papillion"</h2>
                    <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 20px;">
                        "Configure an LLM to power the orchestrator, or skip to use demo mode."
                    </p>

                    <div class="setup-options">
                        <div
                            class=move || if selected_provider.get() == "ollama" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("ollama".into())
                        >
                            <div class="setup-option-title">"Ollama"</div>
                            <div class="setup-option-desc">"Connect to a local Ollama instance"</div>
                        </div>
                        <div
                            class=move || if selected_provider.get() == "openai" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("openai".into())
                        >
                            <div class="setup-option-title">"OpenAI-compatible"</div>
                            <div class="setup-option-desc">"Any API endpoint with OpenAI-style interface"</div>
                        </div>
                        <div
                            class=move || if selected_provider.get() == "none" { "setup-option selected" } else { "setup-option" }
                            on:click=move |_| selected_provider.set("none".into())
                        >
                            <div class="setup-option-title">"Skip for now"</div>
                            <div class="setup-option-desc">"Use demo mode without an LLM"</div>
                        </div>
                    </div>

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
