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
        OrchestratorStatus::Disconnected => "Offline",
        OrchestratorStatus::Unconfigured => "Setup",
    };

    let status_class = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "topbar-status ready",
        _ => "topbar-status offline",
    };

    let toggle_menu = move |_| {
        menu_open.update(|v| *v = !*v);
    };

    let close_menu = move |_| {
        menu_open.set(false);
    };

    let canvases = move || canvas_state.canvases.get();
    let active_id = move || canvas_state.current_canvas_id.get();

    view! {
        <div class="topbar">
            <div class="topbar-left">
                <button class="topbar-menu-btn" on:click=toggle_menu title="Menu">
                    "\u{2630}"
                </button>
                <img src="/logo.png" alt="Papillion" class="topbar-logo" />
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
                <A href="/" attr:class="menu-item menu-item-new" on:click=move |_| {
                    canvas_state.new_canvas();
                    menu_open.set(false);
                }>
                    "+ New Canvas"
                </A>
                <For
                    each=canvases
                    key=|c| c.id.clone()
                    let:canvas
                >
                    {
                        let cid = canvas.id.clone();
                        let cid_for_class = canvas.id.clone();
                        view! {
                            <A
                                href="/"
                                attr:class=move || {
                                    if active_id().as_deref() == Some(&cid_for_class) {
                                        "menu-item active"
                                    } else {
                                        "menu-item"
                                    }
                                }
                                on:click=move |_| {
                                    canvas_state.current_canvas_id.set(Some(cid.clone()));
                                    menu_open.set(false);
                                }
                            >
                                {canvas.name.clone()}
                            </A>
                        }
                    }
                </For>
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
