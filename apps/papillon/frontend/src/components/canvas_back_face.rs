use leptos::prelude::*;

use crate::components::canvas_workflow_pipeline::CanvasWorkflowPipeline;

#[component]
pub fn CanvasBackFace() -> impl IntoView {
    view! {
        <div class="canvas-back-face">
            <div class="back-face-panel">
                <CanvasWorkflowPipeline />
            </div>
        </div>
    }
}
