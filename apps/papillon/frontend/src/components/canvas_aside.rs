use leptos::prelude::*;
use papillon_shared::OrchestratorStatus;

use crate::components::canvas_ghost_run_panel::CanvasGhostRunPanel;
use crate::state::canvas::CanvasState;
use crate::state::orchestrator::OrchestratorState;

/// Newtype wrapper for the aside open signal, so context lookup is unambiguous.
/// Using a newtype avoids collision with `show_settings: RwSignal<bool>` which
/// is provided at the app root with the same underlying type.
#[derive(Clone, Copy)]
pub struct AsideOpen(pub RwSignal<bool>);

#[component]
pub fn CanvasAsideDockToggle(open: RwSignal<bool>) -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();

    let status_class = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => "is-ready",
        OrchestratorStatus::Disconnected => "is-offline",
        OrchestratorStatus::Unconfigured => "is-setup",
        OrchestratorStatus::Downloading { .. } => "is-working",
    };

    view! {
        <Show when=move || !open.get()>
            <button
                class="canvas-dock-toggle"
                type="button"
                title="Open the orchestrator dock"
                aria-label="Open orchestrator dock"
                on:click=move |_| open.set(true)
            >
                <span class=move || format!("canvas-dock-toggle-dot {}", status_class()) />
                <span class="canvas-dock-toggle-label">"Orchestrator"</span>
            </button>
        </Show>
    }
}

/// Collapsible right aside for the canvas front face.
/// Presents the orchestrator as a first-class dock beside the rendered canvas.
#[component]
pub fn CanvasAside(open: RwSignal<bool>) -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let canvas_state = expect_context::<CanvasState>();

    let show_tip = RwSignal::new({
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("papillon_aside_tip_dismissed").ok().flatten())
            .is_none()
    });

    let dismiss_tip = move |_: leptos::ev::MouseEvent| {
        show_tip.set(false);
        if let Some(storage) = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
        {
            let _ = storage.set_item("papillon_aside_tip_dismissed", "1");
        }
    };

    let canvas_name = move || {
        canvas_state
            .current_canvas()
            .map(|canvas| canvas.name)
            .unwrap_or_else(|| "Canvas".into())
    };

    let workflow_count = move || canvas_state.current_canvas_blocks().get().len();

    let orchestrator_status = move || match orchestrator.status.get() {
        papillon_shared::OrchestratorStatus::Ready => "On-device intent planner ready",
        papillon_shared::OrchestratorStatus::Disconnected => "Planner offline",
        papillon_shared::OrchestratorStatus::Unconfigured => "Planner needs setup",
        papillon_shared::OrchestratorStatus::Downloading { .. } => "Planner is downloading",
    };

    view! {
        <div
            class="canvas-aside"
            class:collapsed=move || !open.get()
        >
            <div class="canvas-aside-header">
                <div class="canvas-aside-heading">
                    <span class="canvas-aside-title">"ORCHESTRATOR"</span>
                    <span class="canvas-aside-subtitle">{canvas_name}</span>
                </div>
                <button
                    class="canvas-aside-close"
                    on:click=move |_| open.set(false)
                    aria-label="Close orchestrator"
                >"\u{00d7}"</button>
            </div>

            <div class="canvas-aside-body">
                <Show when=move || show_tip.get()>
                    <div class="canvas-aside-tip">
                        "The dock is where Papillon surfaces approvals, agent choices, and workflow activity so the rendered surface stays clean."
                        <button class="canvas-aside-tip-dismiss" on:click=dismiss_tip>
                            "Got it, dismiss"
                        </button>
                    </div>
                </Show>

                <div class="canvas-aside-status-card">
                    <div class="canvas-aside-status-label">"Status"</div>
                    <div class="canvas-aside-status-copy">{orchestrator_status}</div>
                    <div class="canvas-aside-status-meta">
                        {move || format!("{} workflow steps on this canvas", workflow_count())}
                    </div>
                </div>

                <CanvasGhostRunPanel compact=true />
            </div>
        </div>
    }
}
