use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::address_bar::AddressBar;
use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::{LlmProvider, OrchestratorConfig};

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
            LlmProvider::BuiltIn => selected.set("builtin".into()),
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
            "builtin" => LlmProvider::BuiltIn,
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
                <option value="builtin">"Built-in (coming soon)"</option>
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

    view! {
        <div class="card">
            <h3 style="font-size: 14px; margin-bottom: 12px;">"Identity"</h3>
            <Show
                when=move || identity.info.get().is_some()
                fallback=|| view! {
                    <p style="color: var(--text-secondary);">"Identity auto-generated on startup."</p>
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
