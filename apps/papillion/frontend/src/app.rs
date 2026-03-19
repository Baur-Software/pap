use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::setup_wizard::SetupWizard;
use crate::components::sidebar::Sidebar;
use crate::pages::activity::ActivityPage;
use crate::pages::home::HomePage;
use crate::pages::scenario::ScenarioPage;
use crate::pages::settings::SettingsPage;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use crate::state::registry::RegistryState;
use papillion_shared::{IdentityInfo, OrchestratorStatus};

#[component]
pub fn App() -> impl IntoView {
    let identity_state = IdentityState::new();
    let registry_state = RegistryState::new();
    let orchestrator_state = OrchestratorState::new();
    provide_context(identity_state);
    provide_context(registry_state);
    provide_context(orchestrator_state);

    // Auto-load identity on startup
    Effect::new(move || {
        let identity = identity_state;
        let orchestrator = orchestrator_state;
        spawn_local(async move {
            // Load identity
            if let Ok(info) = bridge::invoke_no_args::<IdentityInfo>("get_identity").await {
                identity.info.set(Some(info));
            }
            // Load orchestrator status
            if let Ok(status) =
                bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status").await
            {
                orchestrator.status.set(status);
            }
        });
    });

    view! {
        <Router>
            <div class="app-shell">
                <header class="header">
                    <img src="logo.png" alt="Papillion" class="header-logo" />
                    <h1>"Papillion"</h1>
                </header>
                <Sidebar />
                <main class="main-content">
                    <Routes fallback=|| "Page not found.">
                        <Route path=path!("/") view=HomePage />
                        <Route path=path!("/scenario/:id") view=ScenarioPage />
                        <Route path=path!("/activity") view=ActivityPage />
                        <Route path=path!("/settings") view=SettingsPage />
                    </Routes>
                </main>
                <footer class="status-bar">
                    <span>"Ready"</span>
                </footer>
            </div>
            <SetupWizard />
        </Router>
    }
}
