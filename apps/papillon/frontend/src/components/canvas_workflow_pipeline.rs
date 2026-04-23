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
pub(crate) fn derive_block_trace(block: &CanvasBlock) -> (&'static str, &'static str, Option<String>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use papillon_shared::{BlockState, CanvasBlock, IntentPlan};

    // ── Fixture helpers ─────────────────────────────────────────────────────

    fn make_block(state: BlockState) -> CanvasBlock {
        CanvasBlock {
            id: "blk-001".into(),
            prompt_id: "p-001".into(),
            prompt_text: Some("What flights are available?".into()),
            state,
            schema_type: None,
            content: None,
            linked_block_ids: vec![],
            agent_did: None,
            created_at: "2026-04-22T00:00:00Z".into(),
            updated_at: "2026-04-22T00:00:00Z".into(),
            mandate_expires_at: None,
            preference_guided: false,
            auto_expand: false,
            retention_warning: None,
        }
    }

    fn make_intent_plan() -> IntentPlan {
        IntentPlan {
            action: "schema:SearchAction".into(),
            selected_agent_name: "Flight Search Agent".into(),
            selected_agent_did: Some("did:web:flights.example".into()),
            requires_disclosure: vec!["schema:Person.name".into(), "schema:Date".into()],
            returns: vec!["schema:FlightReservation".into()],
            approval_request_id: "req-abc-123".into(),
            ttl_hours: 1,
        }
    }

    // ── derive_block_trace: CSS modifier class ───────────────────────────────

    #[test]
    fn resolving_returns_trace_resolving_class() {
        let block = make_block(BlockState::Resolving {
            phase: 2,
            phase_label: "Mandate".into(),
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-resolving");
    }

    #[test]
    fn awaiting_approval_returns_trace_awaiting_class() {
        let block = make_block(BlockState::AwaitingApproval {
            plan: make_intent_plan(),
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-awaiting");
    }

    #[test]
    fn ghost_returns_trace_ghost_class() {
        let block = make_block(BlockState::Ghost {
            agent_name: "Flight Agent".into(),
            action_type: "schema:SearchAction".into(),
            disclosure_preview: vec![],
            returns_preview: vec![],
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-ghost");
    }

    #[test]
    fn resolved_returns_trace_resolved_class() {
        let block = make_block(BlockState::Resolved);
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-resolved");
    }

    #[test]
    fn failed_returns_trace_failed_class() {
        let block = make_block(BlockState::Failed {
            phase: 3,
            reason: "agent_unavailable".into(),
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-failed");
    }

    #[test]
    fn outcome_returns_trace_resolved_class() {
        let block = make_block(BlockState::Outcome {
            provenance_block_ids: vec!["blk-a".into(), "blk-b".into()],
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-resolved");
    }

    #[test]
    fn guide_returns_trace_pending_class() {
        let block = make_block(BlockState::Guide {
            summary: "2 results from flight agents".into(),
            suggestions: vec![],
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-pending");
    }

    #[test]
    fn note_returns_trace_pending_class() {
        let block = make_block(BlockState::Note {
            title: "My note".into(),
            content: "Some content".into(),
            editing: false,
        });
        let (css_class, _, _) = derive_block_trace(&block);
        assert_eq!(css_class, "trace-pending");
    }

    // ── derive_block_trace: badge label ─────────────────────────────────────

    #[test]
    fn resolving_badge_label_is_resolving() {
        let block = make_block(BlockState::Resolving {
            phase: 1,
            phase_label: "Token Presentation".into(),
        });
        let (_, label, _) = derive_block_trace(&block);
        assert_eq!(label, "resolving");
    }

    #[test]
    fn awaiting_approval_badge_label_is_awaiting_approval() {
        let block = make_block(BlockState::AwaitingApproval {
            plan: make_intent_plan(),
        });
        let (_, label, _) = derive_block_trace(&block);
        assert_eq!(label, "awaiting approval");
    }

    #[test]
    fn ghost_badge_label_is_pre_approval() {
        let block = make_block(BlockState::Ghost {
            agent_name: "Test Agent".into(),
            action_type: "schema:SearchAction".into(),
            disclosure_preview: vec![],
            returns_preview: vec![],
        });
        let (_, label, _) = derive_block_trace(&block);
        assert_eq!(label, "pre-approval");
    }

    #[test]
    fn resolved_badge_label_is_done() {
        let block = make_block(BlockState::Resolved);
        let (_, label, _) = derive_block_trace(&block);
        assert_eq!(label, "done");
    }

    #[test]
    fn failed_badge_label_is_failed() {
        let block = make_block(BlockState::Failed {
            phase: 4,
            reason: "timeout".into(),
        });
        let (_, label, _) = derive_block_trace(&block);
        assert_eq!(label, "failed");
    }

    #[test]
    fn outcome_badge_label_is_outcome() {
        let block = make_block(BlockState::Outcome {
            provenance_block_ids: vec![],
        });
        let (_, label, _) = derive_block_trace(&block);
        assert_eq!(label, "outcome");
    }

    // ── derive_block_trace: inline description text ──────────────────────────

    #[test]
    fn resolving_inline_text_contains_phase_label() {
        let block = make_block(BlockState::Resolving {
            phase: 3,
            phase_label: "Disclosure".into(),
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert_eq!(desc, Some("Disclosure".to_string()));
    }

    #[test]
    fn resolving_empty_phase_label_returns_empty_string() {
        let block = make_block(BlockState::Resolving {
            phase: 1,
            phase_label: String::new(),
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert_eq!(desc, Some(String::new()));
    }

    #[test]
    fn awaiting_approval_has_no_inline_text() {
        let block = make_block(BlockState::AwaitingApproval {
            plan: make_intent_plan(),
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert!(desc.is_none());
    }

    #[test]
    fn ghost_inline_text_contains_agent_name() {
        let block = make_block(BlockState::Ghost {
            agent_name: "Skyscanner Agent".into(),
            action_type: "schema:SearchAction".into(),
            disclosure_preview: vec![],
            returns_preview: vec![],
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert_eq!(desc, Some("Agent: Skyscanner Agent".to_string()));
    }

    #[test]
    fn ghost_inline_text_prefixes_with_agent_colon() {
        let block = make_block(BlockState::Ghost {
            agent_name: "X".into(),
            action_type: "".into(),
            disclosure_preview: vec![],
            returns_preview: vec![],
        });
        let (_, _, desc) = derive_block_trace(&block);
        let text = desc.unwrap();
        assert!(
            text.starts_with("Agent: "),
            "expected 'Agent: ' prefix, got '{text}'"
        );
    }

    #[test]
    fn resolved_has_no_inline_text() {
        let block = make_block(BlockState::Resolved);
        let (_, _, desc) = derive_block_trace(&block);
        assert!(desc.is_none());
    }

    #[test]
    fn failed_inline_text_is_the_reason_string() {
        let block = make_block(BlockState::Failed {
            phase: 5,
            reason: "co_sign_mismatch".into(),
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert_eq!(desc, Some("co_sign_mismatch".to_string()));
    }

    #[test]
    fn failed_empty_reason_returns_empty_string() {
        let block = make_block(BlockState::Failed {
            phase: 2,
            reason: String::new(),
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert_eq!(desc, Some(String::new()));
    }

    #[test]
    fn outcome_has_no_inline_text() {
        let block = make_block(BlockState::Outcome {
            provenance_block_ids: vec!["a".into()],
        });
        let (_, _, desc) = derive_block_trace(&block);
        assert!(desc.is_none());
    }

    // ── derive_block_trace: all 6 PAP handshake phases ──────────────────────

    #[test]
    fn resolving_phase_labels_roundtrip_for_all_six_phases() {
        let phase_labels = [
            (1u8, "Token Presentation"),
            (2, "Mandate"),
            (3, "Disclosure"),
            (4, "Execution"),
            (5, "Co-sign Receipt"),
            (6, "Session Close"),
        ];
        for (phase, label) in phase_labels {
            let block = make_block(BlockState::Resolving {
                phase,
                phase_label: label.into(),
            });
            let (css_class, badge, desc) = derive_block_trace(&block);
            assert_eq!(css_class, "trace-resolving", "phase {phase}");
            assert_eq!(badge, "resolving", "phase {phase}");
            assert_eq!(desc, Some(label.to_string()), "phase {phase}");
        }
    }
}
