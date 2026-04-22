use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock, EdgeState, IntentPlan, PortRef, WorkflowEdge};

use crate::state::canvas::{CanvasSide, CanvasState};

/// Back-face orchestration trace.
///
/// Replaces the former MAP/DESIGN pipeline builder. Shows a live per-block trace
/// of the PAP handshake: resolving phases, awaiting-approval plans with disclosure
/// details, completed outcomes, and failures — one entry per active canvas block.
///
/// Clicking "→ view block" on any entry flips to the front face and requests
/// expansion of that block.
#[component]
pub fn CanvasWorkflowPipeline() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let blocks = canvas_state.current_canvas_blocks();
    let has_blocks = move || !blocks.get().is_empty();

    view! {
        <div class="wf-trace-panel">
            <div class="wf-trace-header">
                <span class="wf-trace-title">"ORCHESTRATION"</span>
            </div>
            <Show
                when=has_blocks
                fallback=|| view! {
                    <div class="wf-trace-empty">
                        <p>"No active orchestration."</p>
                        <p class="wf-trace-empty-hint">"Run a prompt to see the trace."</p>
                    </div>
                }
            >
                <div class="wf-trace-list">
                    <For
                        each=move || blocks.get()
                        key=|b| format!("{}@{}", b.id, b.updated_at)
                        children=move |block| view! { <TraceEntry block=block /> }
                    />
                </div>
            </Show>
        </div>
    }
}

/// A single block's trace entry in the orchestration panel.
#[component]
fn TraceEntry(block: CanvasBlock) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let block_id = block.id.clone();
    let bid_jump = block_id.clone();

    let prompt_preview = block
        .prompt_text
        .as_deref()
        .map(|t| {
            if t.chars().count() > 60 {
                let truncated: String = t.chars().take(60).collect();
                format!("{truncated}\u{2026}")
            } else {
                t.to_string()
            }
        })
        .unwrap_or_default();

    let (state_class, state_label, inline_text) = derive_block_trace(&block);

    let approval_plan = if let BlockState::AwaitingApproval { plan } = &block.state {
        Some(plan.clone())
    } else {
        None
    };
    let agent_did = block.agent_did.clone();

    view! {
        <div class=format!("wf-trace-entry {state_class}")>
            <div class="wf-trace-entry-header">
                <span class="wf-trace-prompt">{prompt_preview}</span>
                <span class=format!("wf-trace-state-badge {state_class}")>{state_label}</span>
            </div>

            // Animated phase label for Resolving blocks; description text for others
            {inline_text.map(|label| view! {
                <div class="wf-trace-phase">
                    <span class="wf-phase-dot wf-phase-dot-pulse" />
                    <span class="wf-trace-phase-label">{label}</span>
                </div>
            })}

            // Agent DID — shown as a truncated monospaced chip when available
            {agent_did.map(|did| {
                let truncated = if did.len() > 28 {
                    format!("{}\u{2026}", &did[..28])
                } else {
                    did.clone()
                };
                view! {
                    <div class="wf-trace-agent">
                        <span class="wf-trace-did">{truncated}</span>
                    </div>
                }
            })}

            // Inline approval plan for AwaitingApproval blocks
            {approval_plan.map(|plan| {
                view! { <ApprovalPlanInline plan=plan /> }
            })}

            // Jump to block on front face
            <button
                class="wf-trace-jump"
                on:click=move |_| {
                    canvas_state.canvas_side.set(CanvasSide::Front);
                    canvas_state.requested_expansion.set(Some(bid_jump.clone()));
                }
            >
                "\u{2192} view block"
            </button>
        </div>
    }
}

/// Derive display properties from a block's current state.
/// Returns (CSS modifier class, badge label, optional inline description text).
fn derive_block_trace(block: &CanvasBlock) -> (&'static str, &'static str, Option<String>) {
    match &block.state {
        BlockState::Resolving { phase_label, .. } => (
            "trace-resolving",
            "resolving",
            Some(phase_label.clone()),
        ),
        BlockState::AwaitingApproval { .. } => ("trace-awaiting", "awaiting approval", None),
        BlockState::Ghost { agent_name, .. } => (
            "trace-ghost",
            "pre-approval",
            Some(format!("Agent: {agent_name}")),
        ),
        BlockState::Resolved => ("trace-resolved", "done", None),
        BlockState::Failed { reason, .. } => (
            "trace-failed",
            "failed",
            Some(reason.clone()),
        ),
        BlockState::Outcome { .. } => ("trace-resolved", "outcome", None),
        _ => ("trace-pending", "pending", None),
    }
}

/// Inline approval plan summary shown inside a `trace-awaiting` entry.
/// Displays agent name, required disclosures, return types, and mandate TTL.
#[component]
fn ApprovalPlanInline(plan: IntentPlan) -> impl IntoView {
    view! {
        <div class="wf-approval-plan">
            <div class="wf-plan-agent-row">
                <span class="wf-plan-label">"Agent:"</span>
                <span class="wf-plan-value">{plan.selected_agent_name.clone()}</span>
            </div>
            {plan.requires_disclosure.iter().map(|d| view! {
                <div class="wf-plan-disclosure">
                    <span class="wf-plan-check">"\u{1f512} "</span>
                    <span>{d.clone()}</span>
                </div>
            }).collect::<Vec<_>>()}
            <div class="wf-plan-returns">
                <span class="wf-plan-label">"Returns:"</span>
                <span class="wf-plan-value">{plan.returns.join(", ")}</span>
            </div>
            <div class="wf-plan-ttl">
                <span class="wf-plan-label">"Mandate:"</span>
                <span class="wf-plan-value">{format!("~{}h", plan.ttl_hours)}</span>
            </div>
        </div>
    }
}

/// Inline approval card shown at a paused edge during workflow execution.
/// Appears when a new (output_type, input_type, agent_did) wire has no memex pre-approval.
#[component]
pub fn EdgeApprovalCard(
    /// The edge that is paused awaiting approval
    edge: WorkflowEdge,
    /// Callback fired on "Allow this once" — resume with current agent, no memex write
    on_allow_once: Callback<()>,
    /// Callback fired on "Always allow" — writes ApprovalRecord, then resumes
    on_always_allow: Callback<()>,
    /// Callback fired on "Deny" — orchestrator finds substitute agent
    on_deny: Callback<()>,
) -> impl IntoView {
    let from_label = edge.from_port.label.clone();
    let from_path = edge.from_port.path.clone();
    let to_label = edge.to_port.label.clone();

    view! {
        <div class="wf-approval-card">
            // Agent identity header
            <div class="wf-approval-agent">
                <span class="wf-approval-icon">"\u{1f916}"</span>
                <div class="wf-approval-agent-info">
                    <span class="wf-approval-agent-name">{to_label}</span>
                </div>
                <span class="wf-tee-badge">"\u{2713} TEE"</span>
            </div>

            // Plain English disclosure description
            <p class="wf-approval-prompt">"This agent will receive:"</p>
            <div class="wf-disclosure-list">
                <div class="wf-disclosure-item">
                    <span class="wf-disclosure-label">{from_label}</span>
                    <span class="wf-disclosure-path">{from_path}</span>
                    <span class="wf-disclosure-check">"\u{2713}"</span>
                </div>
            </div>

            // What the agent will NOT see
            <div class="wf-approval-redacted">
                "\u{1f512} Will not see: your name, email, payment details, or any other data."
            </div>

            // Action buttons
            <div class="wf-approval-actions">
                <button
                    class="wf-approval-btn wf-approval-allow-once"
                    on:click=move |_| on_allow_once.run(())
                >
                    "Allow this once"
                </button>
                <button
                    class="wf-approval-btn wf-approval-always-allow"
                    on:click=move |_| on_always_allow.run(())
                >
                    "Always allow \u{1f9e0}"
                </button>
                <button
                    class="wf-approval-btn wf-approval-deny"
                    on:click=move |_| on_deny.run(())
                >
                    "Deny"
                </button>
            </div>
        </div>
    }
}
