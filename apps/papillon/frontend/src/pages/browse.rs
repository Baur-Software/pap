use leptos::prelude::*;

use crate::bridge;
use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;
use crate::state::registry::RegistryState;

#[component]
pub fn BrowsePage() -> impl IntoView {
    let registry = expect_context::<RegistryState>();

    // Auto-connect to local registry on first visit if not already connected.
    // The local registry is always available and contains all built-in agents.
    Effect::new(move || {
        if registry.info.get().is_some() || registry.loading.get() || !bridge::tauri_available() {
            return;
        }
        registry.connect_to("pap://local");
    });

    view! {
        <div class="page">
            <h2 class="page-title">"Browse Registries"</h2>
            <RegistryBrowser />
            <AgentDetail />
        </div>
    }
}
