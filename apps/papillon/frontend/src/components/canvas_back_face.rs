use leptos::prelude::*;

use crate::components::canvas_workflow_pipeline::CanvasWorkflowPipeline;
use crate::components::source_panel::SourcePanel;

/// Back-face container with two tabs: Sources, Workflow.
///
/// - **Sources**  — `SourcePanel`: all resolved blocks as draggable reference chips.
/// - **Workflow** — `CanvasWorkflowPipeline`: live orchestration trace showing per-block
///                  PAP handshake phases, awaiting-approval plans, and outcomes.
#[component]
pub fn CanvasBackFace() -> impl IntoView {
    // "sources" | "workflow"
    let active_tab: RwSignal<&'static str> = RwSignal::new("sources");

    view! {
        <div class="canvas-back-face">
            // Tab bar
            <div class="back-face-tabs" role="tablist">
                {["sources", "workflow"].iter().map(|&tab| {
                    view! {
                        <button
                            class="back-face-tab"
                            class:back-face-tab--active=move || active_tab.get() == tab
                            role="tab"
                            on:click=move |_| active_tab.set(tab)
                        >
                            {match tab {
                                "sources"  => "Sources",
                                _          => "Workflow",
                            }}
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>

            // Tab panels
            <div class="back-face-panel">
                <Show when=move || active_tab.get() == "sources">
                    <SourcePanel />
                </Show>
                <Show when=move || active_tab.get() == "workflow">
                    <CanvasWorkflowPipeline />
                </Show>
            </div>
        </div>
    }
}
