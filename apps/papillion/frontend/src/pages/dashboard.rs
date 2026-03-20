use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::identity::IdentityState;
use crate::state::registry::RegistryState;
use papillion_shared::{AgentInfo, RegistryInfo};

#[component]
pub fn DashboardPage() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let registry = expect_context::<RegistryState>();
    let navigate = use_navigate();

    let has_identity = move || identity.info.get().is_some();

    let browse_builtin = move |_| {
        let nav = navigate.clone();
        registry.current_url.set("pap://builtin".to_string());
        registry.loading.set(true);
        registry.error.set(None);

        spawn_local(async move {
            #[derive(serde::Serialize)]
            struct Args {
                url: String,
            }
            match bridge::invoke::<Args, RegistryInfo>(
                "navigate_registry",
                &Args {
                    url: "pap://builtin".to_string(),
                },
            )
            .await
            {
                Ok(info) => {
                    registry.info.set(Some(info));
                    #[derive(serde::Serialize)]
                    struct ListArgs {
                        registry_url: String,
                    }
                    if let Ok(agents) = bridge::invoke::<ListArgs, Vec<AgentInfo>>(
                        "list_agents",
                        &ListArgs {
                            registry_url: "pap://builtin".to_string(),
                        },
                    )
                    .await
                    {
                        registry.agents.set(agents);
                    }
                }
                Err(e) => registry.error.set(Some(e)),
            }
            registry.loading.set(false);
            nav("/browse", Default::default());
        });
    };

    view! {
        <div>
            <h2 class="page-title">"Dashboard"</h2>

            <div class="card" style="margin-bottom: 16px;">
                <h3 style="font-size: 14px; margin-bottom: 8px;">"Built-in Registry"</h3>
                <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                    "Browse 5 pre-loaded agents including search, travel booking, payments, and AI assistants. No external services required."
                </p>
                <button class="btn btn-primary" on:click=browse_builtin>
                    "Browse Agents"
                </button>
            </div>

            <Show
                when=has_identity
                fallback=move || view! {
                    <div class="card">
                        <p>"Welcome to Papillion \u{2014} the agentic browser."</p>
                        <p style="color: var(--text-secondary); margin-top: 8px;">
                            "Create an identity in Settings to get started, or browse the built-in registry above."
                        </p>
                    </div>
                }
            >
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Connected Registries"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"1"</div>
                    </div>
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Active Sessions"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"0"</div>
                    </div>
                    <div class="card">
                        <div style="color: var(--text-secondary); font-size: 12px;">"Receipts"</div>
                        <div style="font-size: 24px; font-weight: 600; margin-top: 4px;">"0"</div>
                    </div>
                </div>
            </Show>
        </div>
    }
}
