use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::command_palette::CommandPalette;
use crate::components::setup_wizard::SetupWizard;
use crate::components::topbar::TopBar;
use crate::pages::activity::ActivityPage;
use crate::pages::browse::BrowsePage;
use crate::pages::canvas::CanvasPage;
use crate::pages::scenario::ScenarioPage;
use crate::pages::settings::SettingsPage;
use crate::state::canvas::CanvasState;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use crate::state::registry::RegistryState;
use papillion_shared::{IdentityInfo, OrchestratorStatus};

#[component]
pub fn App() -> impl IntoView {
    let identity_state = IdentityState::default();
    let registry_state = RegistryState::default();
    let orchestrator_state = OrchestratorState::default();
    let canvas_state = CanvasState::default();
    provide_context(identity_state);
    provide_context(registry_state);
    provide_context(orchestrator_state);
    provide_context(canvas_state);

    // Auto-load identity on startup
    Effect::new(move || {
        let identity = identity_state;
        let orchestrator = orchestrator_state;
        spawn_local(async move {
            if let Ok(info) = bridge::invoke_no_args::<IdentityInfo>("get_identity").await {
                identity.info.set(Some(info));
            }
            if let Ok(status) =
                bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status").await
            {
                orchestrator.status.set(status);
            }
        });
    });

    // Global keyboard listener for ⌘K
    Effect::new(move || {
        let cb = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
            if (e.meta_key() || e.ctrl_key()) && e.key() == "k" {
                e.prevent_default();
                canvas_state.palette_open.update(|v| *v = !*v);
            }
        });
        let window = web_sys::window().unwrap();
        let _ = window.add_event_listener_with_callback(
            "keydown",
            cb.as_ref().unchecked_ref(),
        );
        cb.forget(); // Leak intentionally — lives for app lifetime
    });

    let orchestrator_for_status = orchestrator_state;
    let status_label = move || match orchestrator_for_status.status.get() {
        OrchestratorStatus::Ready => "Ready",
        OrchestratorStatus::Downloading { progress_pct } => {
            if progress_pct > 0 { "Downloading\u{2026}" } else { "Downloading\u{2026}" }
        }
        OrchestratorStatus::Disconnected => "Disconnected",
        OrchestratorStatus::Unconfigured => "Unconfigured",
    };
    let status_class = move || match orchestrator_for_status.status.get() {
        OrchestratorStatus::Ready => "status-indicator ready",
        OrchestratorStatus::Downloading { .. } => "status-indicator working",
        OrchestratorStatus::Disconnected => "status-indicator offline",
        OrchestratorStatus::Unconfigured => "status-indicator offline",
    };

    view! {
        <Router>
            <div class="app-shell-canvas">
                <TopBar />
                <Routes fallback=|| "Page not found.">
                    <Route path=path!("/") view=CanvasPage />
                    <Route path=path!("/scenario/:id") view=ScenarioPage />
                    <Route path=path!("/activity") view=ActivityPage />
                    <Route path=path!("/settings") view=SettingsPage />
                    <Route path=path!("/browse") view=BrowsePage />
                </Routes>
                <footer class="status-bar">
                    <span class=status_class>{status_label}</span>
                </footer>
            </div>
            <CommandPalette />
            <SetupWizard />
        </Router>
    }
}
