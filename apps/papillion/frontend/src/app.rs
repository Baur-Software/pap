use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
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
use papillion_shared::{IdentityInfo, OrchestratorStatus, ProfileMetadata};

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

    // Auto-load profiles and identity on startup
    Effect::new(move || {
        let identity = identity_state;
        let orchestrator = orchestrator_state;
        if !bridge::tauri_available() {
            return;
        }
        identity.profiles_loading.set(true);
        identity.loading.set(true);
        spawn_local(async move {
            // Load profile list
            if let Ok(profiles) = bridge::invoke_no_args::<Vec<ProfileMetadata>>("list_profiles").await {
                if let Some(active) = profiles.iter().find(|p| p.active) {
                    identity.current_profile_id.set(Some(active.id.clone()));
                }
                identity.profiles.set(profiles);
            }
            identity.profiles_loading.set(false);

            // Load current identity
            if let Ok(info) = bridge::invoke_no_args::<IdentityInfo>("get_identity").await {
                identity.info.set(Some(info));
            }
            identity.loading.set(false);

            // Load orchestrator status
            if let Ok(status) =
                bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status").await
            {
                orchestrator.status.set(status);
            }
        });
    });

    // Detect identity (DID) changes and reset all state
    // This effect triggers when the DID changes, indicating a profile switch
    // When DID changes, we must reset all profile-scoped state to maintain isolation
    let previous_did = RwSignal::new(None::<String>);
    Effect::new(move || {
        let current_did = identity_state.info.get().map(|i| i.did.clone());
        let prev_did = previous_did.get();

        // Only reset if we've loaded an identity before and DID actually changed
        if let (Some(prev), Some(curr)) = (prev_did, &current_did) {
            if prev != *curr {
                // DID changed — clear all profile-scoped state
                // Canvas: Reset to empty workspace
                canvas_state.canvases.set(Vec::new());
                canvas_state.current_canvas_id.set(None);
                canvas_state.reshape_block_id.set(None);
                canvas_state.recent_prompts.set(Vec::new());

                // Registry: Clear current registry state (will reload on next discovery)
                registry_state.current_url.set(String::new());
                registry_state.info.set(None);
                registry_state.agents.set(Vec::new());
                registry_state.selected_agent.set(None);
                registry_state.action_filter.set(String::new());
                registry_state.error.set(None);

                // Reload orchestrator config for new profile
                let orchestrator = orchestrator_state;
                spawn_local(async move {
                    if let Ok(status) =
                        bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status").await
                    {
                        orchestrator.status.set(status);
                    }
                });
            }
        }

        // Track the DID for next comparison
        previous_did.set(current_did);
    });

    // Global keyboard listener for ⌘K — creates a new canvas and navigates home.
    // Uses History pushState + popstate so the Leptos router picks up the change
    // without a full page reload (which would tear down WASM).
    Effect::new(move || {
        let cb = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
            if (e.meta_key() || e.ctrl_key()) && e.key() == "k" {
                e.prevent_default();
                canvas_state.new_canvas();
                if let Some(window) = web_sys::window() {
                    let history = window.history().unwrap();
                    let _ = history.push_state_with_url(&JsValue::NULL, "", Some("/"));
                    let _ = window.dispatch_event(
                        &web_sys::Event::new("popstate").unwrap(),
                    );
                }
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
            <SetupWizard />
        </Router>
    }
}
