use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use std::sync::Arc;

use crate::bridge;
use crate::components::setup_wizard::SetupWizard;
use crate::components::sidebar::Sidebar;
use crate::components::topbar::TopBar;
use crate::pages::activity::ActivityPage;
use crate::pages::browse::BrowsePage;
use crate::pages::canvas::CanvasPage;
use crate::pages::dashboard::DashboardPage;
use crate::pages::home::HomePage;
use crate::pages::scenario::ScenarioPage;
use crate::pages::settings::SettingsPage;
use crate::service::{PapillonService, TauriService, WebService};
use crate::state::canvas::CanvasState;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use crate::state::registry::RegistryState;
use crate::state::templates::TemplatesState;
use papillon_shared::{BlockEvent, IdentityInfo, OrchestratorStatus, ProfileMetadata, Template};

#[component]
pub fn App() -> impl IntoView {
    let identity_state = IdentityState::default();
    let registry_state = RegistryState::default();
    let orchestrator_state = OrchestratorState::default();
    let canvas_state = CanvasState::default();
    let templates_state = TemplatesState::default();
    provide_context(identity_state);
    provide_context(registry_state);
    provide_context(orchestrator_state);
    provide_context(canvas_state);
    provide_context(templates_state);

    // Provide PapillonService context — prevents panic in WASM handshake path.
    // Tauri mode: TauriService delegates to native backend via IPC.
    // Browser mode: WebService starts empty, then loads from IndexedDB asynchronously.
    let service: Arc<dyn PapillonService> = if bridge::tauri_available() {
        Arc::new(TauriService)
    } else {
        Arc::new(WebService::empty())
    };
    provide_context(service.clone());

    // Seed the first canvas if this is a fresh install.
    // Only in Tauri mode — the backend resolves prompts via IPC. In browser mode
    // the WASM handshake has no agents to query, so seed would just panic.
    if bridge::tauri_available() && canvas_state.canvases.get_untracked().is_empty() {
        canvas_state.seed_first_canvas();
    }

    // WASM browser startup — initialize identity from IndexedDB
    if !bridge::tauri_available() {
        let identity = identity_state;
        let orchestrator = orchestrator_state;
        let svc = service;
        spawn_local(async move {
            // Load profiles and identity from IndexedDB (auto-creates default if needed)
            if let Err(e) = svc.initialize().await {
                web_sys::console::error_1(&format!("Service init failed: {e}").into());
            }

            // Populate identity signals from the now-initialized service
            if let Ok(profiles) = svc.list_profiles().await {
                if let Some(active) = profiles.iter().find(|p| p.active) {
                    identity.current_profile_id.set(Some(active.id.clone()));
                }
                identity.profiles.set(profiles);
            }
            if let Ok(info) = svc.get_identity().await {
                identity.info.set(Some(info));
            }

            // No backend orchestrator in browser mode
            orchestrator.status.set(OrchestratorStatus::Unconfigured);
        });
    }

    // Auto-load profiles and identity on startup (Tauri path)
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
            if let Ok(profiles) =
                bridge::invoke_no_args::<Vec<ProfileMetadata>>("list_profiles").await
            {
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

            // Auto-connect to the local registry so agents are immediately
            // available in the Browse page and for canvas workflow resolution.
            registry_state.connect_to("pap://local");
        });
    });

    // Listen for backend block events (handshake phase progress + results).
    // These events are emitted by the Rust backend during the 6-phase handshake
    // and are the only way the frontend learns about phase transitions and results
    // when running inside Tauri (the WASM path updates signals directly instead).
    if bridge::tauri_available() {
        let cs = canvas_state;
        bridge::listen::<BlockEvent>("block_updated", move |event| {
            cs.apply_block_event(event.block);
        });
        let cs = canvas_state;
        bridge::listen::<BlockEvent>("block_resolved", move |event| {
            cs.apply_block_event(event.block);
        });
    }

    // Load global templates on startup
    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        spawn_local(async move {
            if let Ok(templates) = bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
            {
                templates_state.global_templates.set(templates);
            }
        });
    });

    // Detect identity (DID) changes and reset all state
    // This effect triggers when the DID changes, indicating a profile switch
    // When DID changes, we must reset all profile-scoped state to maintain isolation
    let previous_did = RwSignal::new(None::<String>);
    Effect::new(move || {
        let current_did = identity_state.info.get().map(|i| i.did.clone());
        // Use get_untracked to avoid infinite reactive cycle:
        // this effect writes to previous_did, so reading it tracked
        // would re-trigger the effect on every write.
        let prev_did = previous_did.get_untracked();

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

                // Templates: Clear profile-scoped templates (will reload below)
                templates_state.profile_templates.set(Vec::new());

                // Reload orchestrator config for new profile
                let orchestrator = orchestrator_state;
                spawn_local(async move {
                    if let Ok(status) =
                        bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status")
                            .await
                    {
                        orchestrator.status.set(status);
                    }
                });

                // Reconnect to local registry after profile switch
                registry_state.connect_to("pap://local");
            }
        }

        // Track the DID for next comparison
        previous_did.set(current_did);
    });

    // Load profile templates when identity changes
    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        let current_did = identity_state.info.get().map(|i| i.did.clone());
        if let Some(did) = current_did {
            spawn_local(async move {
                if let Ok(templates) = bridge::invoke::<serde_json::Value, Vec<Template>>(
                    "get_profile_templates",
                    &serde_json::json!({ "principal_did": did }),
                )
                .await
                {
                    templates_state.profile_templates.set(templates);
                }
            });
        }
    });

    // Global keyboard listener for ⌘K — creates a new canvas and navigates home.
    // Uses History pushState + popstate so the Leptos router picks up the change
    // without a full page reload (which would tear down WASM).
    Effect::new(move || {
        let cb =
            Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
                if (e.meta_key() || e.ctrl_key()) && e.key() == "k" {
                    e.prevent_default();
                    canvas_state.new_canvas();
                    if let Some(window) = web_sys::window() {
                        let history = window.history().unwrap();
                        let _ = history.push_state_with_url(&JsValue::NULL, "", Some("/"));
                        let _ = window.dispatch_event(&web_sys::Event::new("popstate").unwrap());
                    }
                }
            });
        let window = web_sys::window().unwrap();
        let _ = window.add_event_listener_with_callback("keydown", cb.as_ref().unchecked_ref());
        cb.forget(); // Leak intentionally — lives for app lifetime
    });

    let orchestrator_for_status = orchestrator_state;
    let status_label = move || match orchestrator_for_status.status.get() {
        OrchestratorStatus::Ready => "Ready",
        OrchestratorStatus::Downloading { progress_pct } => {
            let _ = progress_pct;
            "Downloading\u{2026}"
        }
        OrchestratorStatus::Disconnected => "Agents only",
        OrchestratorStatus::Unconfigured => "Agents only",
    };
    let status_class = move || match orchestrator_for_status.status.get() {
        OrchestratorStatus::Ready => "status-indicator ready",
        OrchestratorStatus::Downloading { .. } => "status-indicator working",
        _ => "status-indicator ready",
    };

    view! {
        <Router>
            <div class="app-shell-canvas">
                <TopBar />
                <Sidebar />
                <main class="app-main">
                    <Routes fallback=|| "Page not found.">
                        <Route path=path!("/") view=CanvasPage />
                        <Route path=path!("/home") view=HomePage />
                        <Route path=path!("/scenario/:id") view=ScenarioPage />
                        <Route path=path!("/activity") view=ActivityPage />
                        <Route path=path!("/settings") view=SettingsPage />
                        <Route path=path!("/browse") view=BrowsePage />
                        <Route path=path!("/fleet") view=DashboardPage />
                    </Routes>
                </main>
                <footer class="status-bar app-statusbar">
                    <span class="status-bar-item active">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="5"/></svg>
                        "ZERO_TRUST_ENFORCED"
                    </span>
                    <span class="status-bar-sep">"|"</span>
                    <span class="status-bar-item">"LOCAL_VAULT_ENCRYPTED"</span>
                    <span class="status-bar-sep">"|"</span>
                    <span class="status-bar-item">"NO_TELEMETRY"</span>
                    <span class="status-bar-spacer" />
                    <span class="status-bar-item">"PAPILLON_v0.5.7"</span>
                    <span class="status-bar-sep">"|"</span>
                    <span class=move || format!("status-bar-item {}", status_class())>{status_label}</span>
                </footer>
            </div>
            <SetupWizard />
        </Router>
    }
}
