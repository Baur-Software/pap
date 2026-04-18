use leptos::prelude::*;

use crate::state::canvas::CanvasState;

/// Workflow pipeline — lists all blocks as workflow cards on the back face.
#[component]
pub fn CanvasWorkflowPipeline() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks)
            .unwrap_or_default()
    };

    let has_blocks = move || !blocks().is_empty();

    view! {
        <div class="canvas-workflow-pipeline">
            <Show
                when=has_blocks
                fallback=move || view! {
                    <div class="workflow-empty-state">
                        "No blocks yet. Switch to Rendered view and submit a prompt."
                    </div>
                }
            >
                <For
                    each=blocks
                    key=|b| format!("{}@{}", b.id, b.updated_at)
                    children=move |block| {
                        let block_id = block.id.clone();
                        let block_id_retry = block_id.clone();
                        let state_label = match &block.state {
                            papillon_shared::BlockState::Resolved => "resolved",
                            papillon_shared::BlockState::Resolving { .. } => "resolving",
                            papillon_shared::BlockState::Failed { .. } => "failed",
                            papillon_shared::BlockState::Ghost { .. } => "ghost",
                            papillon_shared::BlockState::AwaitingApproval { .. } => "resolving",
                            papillon_shared::BlockState::Outcome { .. } => "resolved",
                            papillon_shared::BlockState::Guide { .. } => "guide",
                            papillon_shared::BlockState::Note { .. } => "note",
                        };
                        let badge_class = format!("wf-state-badge {}", state_label);
                        let query = block.prompt_text.clone().unwrap_or_else(|| block_id.clone());
                        let schema = block.schema_type.clone().unwrap_or_default();
                        let agent = block.agent_did.clone().unwrap_or_default();
                        let agent_short = if agent.len() > 20 {
                            format!("{}...", &agent[..20])
                        } else {
                            agent.clone()
                        };
                        let expires = block.mandate_expires_at.clone().unwrap_or_default();
                        let has_agent = !agent.is_empty();
                        let has_expires = !expires.is_empty();
                        let id_short = if block_id.len() > 8 {
                            format!("{}...", &block_id[..8])
                        } else {
                            block_id.clone()
                        };
                        view! {
                            <div class="workflow-block-card">
                                <div class="wf-header-row">
                                    <span class="wf-meta">{id_short}</span>
                                    {move || {
                                        if !schema.is_empty() {
                                            view! {
                                                <span class="wf-meta">
                                                    {format!(" \u{00b7} {}", schema.trim_start_matches("schema:"))}
                                                </span>
                                            }.into_any()
                                        } else {
                                            view! { <span /> }.into_any()
                                        }
                                    }}
                                    <span class=badge_class>{state_label}</span>
                                </div>
                                <div class="wf-query">{query}</div>
                                <Show when=move || has_agent>
                                    <div class="wf-meta">{agent_short.clone()}</div>
                                </Show>
                                <Show when=move || has_expires>
                                    <div class="wf-meta">{format!("expires {}", &expires[..16.min(expires.len())])}</div>
                                </Show>
                                <button
                                    class="btn-retry"
                                    on:click=move |e: leptos::ev::MouseEvent| {
                                        e.stop_propagation();
                                        canvas_state.retry_block(block_id_retry.clone());
                                    }
                                >
                                    "Re-run"
                                </button>
                            </div>
                        }
                    }
                />
            </Show>
        </div>
    }
}
