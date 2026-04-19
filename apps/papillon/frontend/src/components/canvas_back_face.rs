use leptos::prelude::*;

use crate::components::canvas_workflow_pipeline::CanvasWorkflowPipeline;
use crate::components::pipeline_builder_tab::PipelineBuilderTab;
use crate::components::source_panel::SourcePanel;

/// Back-face container with three tabs: Sources, Build, History.
///
/// - **Sources** — `SourcePanel`: all resolved blocks as draggable reference chips.
/// - **Build**   — `PipelineBuilderTab`: run saved pipelines with synthesis format control.
/// - **History** — `CanvasWorkflowPipeline`: the existing block list (moved here).
#[component]
pub fn CanvasBackFace() -> impl IntoView {
    // "sources" | "build" | "history"
    let active_tab: RwSignal<&'static str> = RwSignal::new("sources");

    view! {
        <div class="canvas-back-face">
            // Tab bar
            <div class="back-face-tabs" role="tablist">
                {["sources", "build", "history"].iter().map(|&tab| {
                    view! {
                        <button
                            class="back-face-tab"
                            class:back-face-tab--active=move || active_tab.get() == tab
                            role="tab"
                            on:click=move |_| active_tab.set(tab)
                        >
                            {match tab {
                                "sources" => "Sources",
                                "build"   => "Build",
                                _         => "History",
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
                <Show when=move || active_tab.get() == "build">
                    <PipelineBuilderTab />
                </Show>
                <Show when=move || active_tab.get() == "history">
                    <CanvasWorkflowPipeline />
                </Show>
            </div>
        </div>
    }
}
