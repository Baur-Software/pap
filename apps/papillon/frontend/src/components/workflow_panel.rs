use leptos::prelude::*;
use crate::state::canvas::CanvasState;
use crate::components::workflow_chat_thread::WorkflowChatThread;
use crate::components::agent_curation_list::AgentCurationList;
use crate::components::disclosure_form::DisclosureForm;

/// Slide-in workflow panel from the right side.
/// Shows chat, curation, and disclosure sections for the active workflow.
#[component]
pub fn WorkflowPanel() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let is_open = canvas_state.workflow_panel_open;

    // Active plan from CanvasState (populated by canvas_plan_prompt command)
    let active_plan = canvas_state.active_intent_plan;

    // Close handler
    let close = move |_| {
        canvas_state.workflow_panel_open.set(false);
    };

    view! {
        <div
            class="workflow-panel-backdrop"
            class:open=move || is_open.get()
            on:click=close
        />

        <div
            class="workflow-panel"
            class:open=move || is_open.get()
        >
            <div class="workflow-panel-header">
                <h2>"Workflow"</h2>
                <button
                    class="workflow-panel-close"
                    on:click=close
                    aria-label="Close workflow panel"
                >
                    "×"
                </button>
            </div>

            <div class="workflow-panel-body">
                <Show
                    when=move || active_plan.get().is_some()
                    fallback=|| view! {
                        <div class="workflow-no-plan">
                            "No active plan"
                        </div>
                    }
                >
                    {move || {
                        active_plan.get().map(|plan| {
                            // Create selected agents signal for this plan
                            let selected_agents = RwSignal::new(Vec::<String>::new());

                            view! {
                                {/* Chat section */}
                                <div class="workflow-section workflow-chat-section">
                                    <h3>"Chat"</h3>
                                    <WorkflowChatThread />
                                </div>

                                {/* Curation section */}
                                <div class="workflow-section workflow-curation-section">
                                    <h3>"Curation"</h3>
                                    <AgentCurationList plan=plan.clone() selected_agents=selected_agents />
                                </div>

                                {/* Disclosure section */}
                                <div class="workflow-section workflow-disclosure-section">
                                    <h3>"Disclosure"</h3>
                                    <DisclosureForm plan=plan selected_agents=selected_agents.read_only() />
                                </div>
                            }
                        })
                    }}
                </Show>
            </div>

            <div class="workflow-panel-footer">
                <button
                    class="workflow-execute-button"
                    disabled=true
                >
                    "Disclose & Execute"
                </button>
            </div>
        </div>
    }
}
