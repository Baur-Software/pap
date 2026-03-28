use leptos::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;
use crate::state::registry::RegistryState;
use papillon_shared::{AgentInfo, RegistryInfo};

#[component]
pub fn BrowsePage() -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    // Auto-connect to local registry on first visit if not already connected.
    // The local registry is always available and contains all built-in agents.
    Effect::new(move || {
        if registry.info.get().is_some() || registry.loading.get() || !bridge::tauri_available() {
            return;
        }
        registry.current_url.set("pap://local".to_string());
        registry.loading.set(true);

        spawn_local(async move {
            #[derive(serde::Serialize)]
            struct Args {
                url: String,
            }
            match bridge::invoke::<Args, RegistryInfo>(
                "navigate_registry",
                &Args {
                    url: "pap://local".to_string(),
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
                            registry_url: "pap://local".to_string(),
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
        });
    });

    view! {
        <div class="page">
            <h2 class="page-title">"Browse Registries"</h2>
            <RegistryBrowser />
            <AgentDetail />
        </div>
    }
}
