use leptos::prelude::*;

use crate::components::registry::agent_detail::AgentDetail;
use crate::components::registry::browser::RegistryBrowser;

#[component]
pub fn BrowsePage() -> impl IntoView {
    view! {
        <div>
            <h2 class="page-title">"Browse Registries"</h2>
            <RegistryBrowser />
            <AgentDetail />
        </div>
    }
}
