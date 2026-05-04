use leptos::prelude::*;

use crate::components::canvas_workflow_pipeline::CanvasWorkflowPipeline;
use crate::components::source_panel::SourcePanel;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BackFaceTab {
    Sources,
    Workflow,
}

#[derive(Clone, Copy)]
struct BackFaceContext {
    active_tab: RwSignal<BackFaceTab>,
}

#[component]
pub fn CanvasBackFace() -> impl IntoView {
    let active_tab: RwSignal<BackFaceTab> = RwSignal::new(BackFaceTab::Workflow);
    provide_context(BackFaceContext { active_tab });

    view! {
        <div class="canvas-back-face">
            <BackFaceTabs />
            <BackFacePanel />
        </div>
    }
}

#[component]
fn BackFaceTabs() -> impl IntoView {
    view! {
        <div class="back-face-tabs" role="tablist" aria-label="Canvas back face">
            <BackFaceTabButton tab=BackFaceTab::Sources label="Sources" />
            <BackFaceTabButton tab=BackFaceTab::Workflow label="Workflow" />
        </div>
    }
}

#[component]
fn BackFaceTabButton(tab: BackFaceTab, label: &'static str) -> impl IntoView {
    let back_face = expect_context::<BackFaceContext>();

    view! {
        <button
            class="back-face-tab"
            class:back-face-tab--active=move || back_face.active_tab.get() == tab
            type="button"
            role="tab"
            aria-selected=move || (back_face.active_tab.get() == tab).to_string()
            tabindex=move || if back_face.active_tab.get() == tab { "0" } else { "-1" }
            on:click=move |_| back_face.active_tab.set(tab)
        >
            {label}
        </button>
    }
}

#[component]
fn BackFacePanel() -> impl IntoView {
    let back_face = expect_context::<BackFaceContext>();

    view! {
        <div class="back-face-panel">
            <Show when=move || back_face.active_tab.get() == BackFaceTab::Sources>
                <SourcePanel />
            </Show>
            <Show when=move || back_face.active_tab.get() == BackFaceTab::Workflow>
                <CanvasWorkflowPipeline />
            </Show>
        </div>
    }
}
