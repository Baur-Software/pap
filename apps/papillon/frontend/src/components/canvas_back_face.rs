use leptos::prelude::*;

use crate::components::canvas_workflow_pipeline::CanvasWorkflowPipeline;
use crate::components::source_panel::SourcePanel;
use crate::state::canvas::CanvasState;

/// Back-face container: Workflow (full-width) + Sources aside on the right.
///
/// Sources are placed here so the user can reference resolved blocks while
/// building / inspecting the workflow graph, without navigating away.
/// The aside is collapsible via the toggle button.
#[component]
pub fn CanvasBackFace() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let sources_open: RwSignal<bool> = RwSignal::new(true);

    // Hide sources aside when canvas has no resolved blocks
    let has_resolved = move || {
        use papillon_shared::BlockState;
        canvas_state
            .current_canvas()
            .map(|c| {
                c.blocks
                    .iter()
                    .any(|b| matches!(b.state, BlockState::Resolved | BlockState::Outcome { .. } | BlockState::Note { .. }))
            })
            .unwrap_or(false)
    };

    view! {
        <div class="canvas-back-face">
            // Main workflow area
            <div class="back-face-workflow">
                <CanvasWorkflowPipeline />
            </div>

            // Sources aside — only when resolved blocks exist
            <Show when=has_resolved>
                <div
                    class="back-face-sources-aside"
                    class:collapsed=move || !sources_open.get()
                >
                    <div class="back-face-sources-header">
                        <span class="back-face-sources-title">"Sources"</span>
                        <button
                            class="back-face-sources-toggle"
                            on:click=move |_| sources_open.update(|v| *v = !*v)
                            title=move || if sources_open.get() { "Collapse sources" } else { "Expand sources" }
                        >
                            {move || if sources_open.get() { "\u{00d7}" } else { "\u{22ee}" }}
                        </button>
                    </div>
                    <Show when=move || sources_open.get()>
                        <SourcePanel />
                    </Show>
                </div>
            </Show>
        </div>
    }
}
