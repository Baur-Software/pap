use leptos::prelude::*;
use leptos_router::components::A;

use crate::state::canvas::CanvasState;
use crate::state::identity::IdentityState;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::OrchestratorStatus;

#[component]
pub fn TopBar() -> impl IntoView {
    let identity = expect_context::<IdentityState>();
    let orchestrator = expect_context::<OrchestratorState>();
    let canvas_state = expect_context::<CanvasState>();
    let menu_open = RwSignal::new(false);

    let did_display = move || {
        identity
            .info
            .get()
            .map(|i| {
                let did = &i.did;
                if did.len() > 20 {
                    format!("{}...{}", &did[..8], &did[did.len() - 6..])
                } else {
                    did.clone()
                }
            })
            .unwrap_or_else(|| "No identity".to_string())
    };

    let status_label = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "Ready",
        OrchestratorStatus::Downloading { .. } => "Downloading...",
        OrchestratorStatus::Offline => "Offline",
        OrchestratorStatus::Disconnected => "Offline",
        OrchestratorStatus::Unconfigured => "Setup",
    };

    let status_class = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "topbar-status ready",
        OrchestratorStatus::Offline => "topbar-status offline",
        _ => "topbar-status offline",
    };

    let toggle_menu = move |_| {
        menu_open.update(|v| *v = !*v);
    };

    let close_menu = move |_| {
        menu_open.set(false);
    };

    let canvases = move || canvas_state.canvases.get();

    view! {
        <div class="topbar">
            <div class="topbar-left">
                <button class="topbar-menu-btn" on:click=toggle_menu title="Menu">
                    "\u{2630}"
                </button>
                <span class="topbar-identity">{did_display}</span>
            </div>
            <div class="topbar-right">
                <span class=status_class>{status_label}</span>
                <A href="/settings" attr:class="topbar-settings-btn" attr:title="Settings">
                    "\u{2699}"
                </A>
            </div>
        </div>
        <Show when=move || menu_open.get()>
            <div class="menu-backdrop" on:click=close_menu></div>
            <div class="menu-dropdown">
                <div class="menu-section-label">"Canvases"</div>
                <For
                    each=canvases
                    key=|c| c.id.clone()
                    let:canvas
                >
                    <button
                        class="menu-item"
                        on:click=move |_| {
                            canvas_state.current_canvas_id.set(Some(canvas.id.clone()));
                            menu_open.set(false);
                        }
                    >
                        {canvas.name.clone()}
                    </button>
                </For>
                <Show when=move || canvases().is_empty()>
                    <div class="menu-item" style="opacity: 0.4; cursor: default;">
                        "No canvases yet"
                    </div>
                </Show>
                <div class="menu-divider"></div>
                <A href="/browse" attr:class="menu-item" on:click=close_menu>
                    "Browse Registries"
                </A>
                <A href="/settings" attr:class="menu-item" on:click=close_menu>
                    "Settings"
                </A>
            </div>
        </Show>
    }
}
