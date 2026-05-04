use leptos::prelude::*;
use papillon_shared::{BlockState, OrchestratorStatus};

use crate::components::canvas_chat_thread::CanvasChatThread;
use crate::components::canvas_workflow_pipeline::{derive_block_trace, ApprovalPlanInline};
use crate::state::canvas::{filter_messages_by_canvas, CanvasState};
use crate::state::orchestrator::OrchestratorState;

#[component]
pub fn CanvasGhostRunPanel(#[prop(optional)] compact: bool) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let orchestrator = expect_context::<OrchestratorState>();

    let active_blocks = move || canvas_state.current_canvas_blocks().get();

    let active_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        filter_messages_by_canvas(&canvas_state.canvas_messages.get(), active_id.as_deref())
    };

    let approvals = move || {
        active_blocks()
            .into_iter()
            .filter_map(|block| match block.state.clone() {
                BlockState::AwaitingApproval { plan } => Some((block, plan)),
                _ => None,
            })
            .collect::<Vec<_>>()
    };

    let trace_blocks = move || {
        active_blocks()
            .into_iter()
            .filter(|block| !matches!(block.state, BlockState::Guide { .. }))
            .collect::<Vec<_>>()
    };

    let summary = move || {
        let blocks = active_blocks();
        let total = blocks.len();
        let resolving = blocks
            .iter()
            .filter(|b| matches!(b.state, BlockState::Resolving { .. } | BlockState::Ghost { .. }))
            .count();
        let approvals = blocks
            .iter()
            .filter(|b| matches!(b.state, BlockState::AwaitingApproval { .. }))
            .count();
        let resolved = blocks
            .iter()
            .filter(|b| matches!(b.state, BlockState::Resolved | BlockState::Outcome { .. }))
            .count();
        (total, resolving, approvals, resolved)
    };

    let orchestrator_badge = move || match orchestrator.status.get() {
        OrchestratorStatus::Ready => ("status-ready".to_string(), "ready".to_string()),
        OrchestratorStatus::Disconnected => (
            "status-disconnected".to_string(),
            "offline".to_string(),
        ),
        OrchestratorStatus::Unconfigured => (
            "status-unconfigured".to_string(),
            "setup needed".to_string(),
        ),
        OrchestratorStatus::Downloading { progress_pct } => {
            if progress_pct >= 100 {
                ("status-disconnected".to_string(), "loading".to_string())
            } else {
                ("status-downloading".to_string(), format!("{progress_pct}%"))
            }
        }
    };

    view! {
        <div class="ghost-run-panel" class:compact=compact>
            <Show when=move || !compact>
                <div class="ghost-run-hero">
                    <div>
                        <div class="ghost-run-kicker">"Orchestrator"</div>
                        <h3 class="ghost-run-title">
                            "Papillon makes the workflow visible before anything is rendered."
                        </h3>
                        <p class="ghost-run-copy">
                            "Agent matches, requested disclosures, workflow steps, and activity stay here so the rendered surface only shows approved values."
                        </p>
                    </div>
                    <span class=move || format!("ghost-run-status {}", orchestrator_badge().0)>
                        {move || orchestrator_badge().1.clone()}
                    </span>
                </div>

                <div class="ghost-run-metrics">
                    <GhostMetric label="Steps" value=move || summary().0 />
                    <GhostMetric label="Working" value=move || summary().1 />
                    <GhostMetric label="Approvals" value=move || summary().2 />
                    <GhostMetric label="Rendered" value=move || summary().3 />
                </div>
            </Show>

            <Show when=move || !approvals().is_empty()>
                <section class="ghost-run-section">
                    <div class="ghost-run-section-header">
                        <span class="ghost-run-section-label">"Approvals"</span>
                        <span class="ghost-run-section-count">{move || approvals().len()}</span>
                    </div>
                    <div class="ghost-run-approvals">
                        <For
                            each=approvals
                            key=|(block, _)| block.id.clone()
                            children=move |(block, plan)| {
                                view! {
                                    <article class="ghost-approval-card">
                                        <div class="ghost-approval-prompt">
                                            {block.prompt_text.unwrap_or_else(|| "Pending approval".into())}
                                        </div>
                                        <ApprovalPlanInline plan=plan />
                                    </article>
                                }
                            }
                        />
                    </div>
                </section>
            </Show>

            <section class="ghost-run-section">
                <div class="ghost-run-section-header">
                    <span class="ghost-run-section-label">"Workflow activity"</span>
                    <span class="ghost-run-section-count">{move || trace_blocks().len()}</span>
                </div>
                <Show
                    when=move || !trace_blocks().is_empty()
                    fallback=move || view! {
                        <div class="ghost-run-empty">
                            "Ask Papillon to browse, resolve, or build something and the workflow activity will appear here."
                        </div>
                    }
                >
                    <div class="ghost-run-trace">
                        <For
                            each=trace_blocks
                            key=|block| block.id.clone()
                            children=move |block| {
                                let (trace_class, badge, detail) = derive_block_trace(&block);
                                view! {
                                    <article class=format!("ghost-trace-card {trace_class}")>
                                        <div class="ghost-trace-header">
                                            <div class="ghost-trace-prompt">
                                                {block.prompt_text.clone().unwrap_or_else(|| "Workflow step".into())}
                                            </div>
                                            <span class="ghost-trace-badge">{badge}</span>
                                        </div>
                                        {detail.map(|text| view! {
                                            <div class="ghost-trace-detail">{text}</div>
                                        })}
                                    </article>
                                }
                            }
                        />
                    </div>
                </Show>
            </section>

            <section class="ghost-run-section ghost-run-activity">
                <div class="ghost-run-section-header">
                    <span class="ghost-run-section-label">"Orchestrator activity"</span>
                    <span class="ghost-run-section-count">{move || active_messages().len()}</span>
                </div>
                <CanvasChatThread compact=compact />
            </section>
        </div>
    }
}

#[component]
fn GhostMetric<F>(label: &'static str, value: F) -> impl IntoView
where
    F: Fn() -> usize + Send + Sync + 'static,
{
    view! {
        <div class="ghost-metric">
            <div class="ghost-metric-value">{value}</div>
            <div class="ghost-metric-label">{label}</div>
        </div>
    }
}
