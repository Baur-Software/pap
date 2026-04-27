use leptos::prelude::*;
use papillon_shared::{
    BlockState, CanvasBlock, EdgeState, IntentPlan, WorkflowEdge, WorkflowMode, WorkflowNode,
};
use wasm_bindgen_futures::spawn_local;

#[allow(unused_imports)]
use js_sys;

use crate::bridge;
use crate::state::canvas::{CanvasSide, CanvasState};

/// Workflow tab — MAP/DESIGN dual-mode pipeline builder.
///
/// * **MAP mode** (default): reactive graph derived from active canvas blocks.
///   Shows one node per resolved/resolving block, edges from `{{block:ID}}` refs and
///   `linked_block_ids`, and inline approval cards for `Proposed` edges.
/// * **DESIGN mode**: interactive canvas where users author a workflow from scratch —
///   add agent nodes, draw wires, then run the designed pipeline.
#[component]
pub fn CanvasWorkflowPipeline() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let mode = canvas_state.workflow_mode;

    view! {
        <div class="wf-panel">
            // Mode toggle bar
            <div class="wf-mode-toggle">
                <button
                    class=move || {
                        if mode.get() == WorkflowMode::Map {
                            "wf-mode-btn active"
                        } else {
                            "wf-mode-btn"
                        }
                    }
                    on:click=move |_| mode.set(WorkflowMode::Map)
                >
                    "MAP"
                </button>
                <button
                    class=move || {
                        if mode.get() == WorkflowMode::Design {
                            "wf-mode-btn active"
                        } else {
                            "wf-mode-btn"
                        }
                    }
                    on:click=move |_| mode.set(WorkflowMode::Design)
                >
                    "DESIGN"
                </button>
            </div>

            // Mode bodies
            <Show
                when=move || mode.get() == WorkflowMode::Map
                fallback=move || view! { <WorkflowDesignMode /> }
            >
                <WorkflowMapMode />
            </Show>
        </div>
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAP MODE
// ─────────────────────────────────────────────────────────────────────────────

/// MAP mode — renders the reactive workflow graph derived from canvas blocks.
#[component]
fn WorkflowMapMode() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let graph = canvas_state.workflow_graph;

    let has_nodes = move || !graph.get().nodes.is_empty();

    view! {
        <div class="wf-graph-canvas">
            <Show
                when=has_nodes
                fallback=|| view! {
                    <div class="wf-graph-empty">
                        <p>"No workflow graph yet."</p>
                        <p class="wf-graph-empty-hint">
                            "Run prompts on the canvas — blocks appear here as nodes."
                        </p>
                    </div>
                }
            >
                <div class="wf-graph-row">
                    // Nodes
                    <For
                        each=move || graph.get().nodes
                        key=|n| n.id.clone()
                        children=move |node| view! { <WorkflowNodeCard node=node /> }
                    />
                </div>
                // Edges / approval cards
                <For
                    each=move || graph.get().edges
                    key=|e| e.id.clone()
                    children=move |edge| view! { <MapEdgeRow edge=edge /> }
                />
            </Show>
        </div>
    }
}

/// Renders a single workflow node card in MAP mode.
#[component]
fn WorkflowNodeCard(node: WorkflowNode) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let node_id = node.id.clone();

    // Derive badge state from the graph; fall back to block state if needed.
    // For MAP mode, node.id == block.id, so we look up the block.
    let badge_class = {
        let nid = node_id.clone();
        move || {
            let blocks = canvas_state.current_canvas_blocks().get();
            if let Some(block) = blocks.iter().find(|b| b.id == nid) {
                match &block.state {
                    BlockState::Resolved => "wf-node-badge resolved",
                    BlockState::Resolving { .. } => "wf-node-badge running",
                    BlockState::Failed { .. } => "wf-node-badge failed",
                    _ => "wf-node-badge pending",
                }
            } else {
                "wf-node-badge pending"
            }
        }
    };

    let badge_label = {
        let nid = node_id.clone();
        move || {
            let blocks = canvas_state.current_canvas_blocks().get();
            if let Some(block) = blocks.iter().find(|b| b.id == nid) {
                match &block.state {
                    BlockState::Resolved => "done",
                    BlockState::Resolving { .. } => "running",
                    BlockState::Failed { .. } => "failed",
                    BlockState::AwaitingApproval { .. } => "awaiting",
                    BlockState::Ghost { .. } => "preview",
                    _ => "pending",
                }
            } else {
                "pending"
            }
        }
    };

    let agent_label = node
        .agent_name
        .clone()
        .unwrap_or_else(|| node.intent.clone());

    let jump_id = node_id.clone();

    view! {
        <div class="wf-node">
            <div class="wf-node-header">
                <span class="wf-node-emoji">"🤖"</span>
                <span class="wf-node-name">{agent_label}</span>
                <span class=badge_class>{badge_label}</span>
            </div>

            // Action type URI
            {(!node.action_type.is_empty()).then(|| view! {
                <div class="wf-node-uri">{node.action_type.clone()}</div>
            })}

            // Input ports
            {(!node.input_ports.is_empty()).then(|| {
                let ports = node.input_ports.clone();
                view! {
                    <div class="wf-node-section">
                        {ports.into_iter().map(|p| view! {
                            <div class="wf-port-row">
                                <span class="wf-port-dot" />
                                <span class="wf-port-label">{p.label.clone()}</span>
                                <span class="wf-port-schema">{p.path.clone()}</span>
                            </div>
                        }).collect::<Vec<_>>()}
                    </div>
                }
            })}

            // Output ports
            {(!node.output_ports.is_empty()).then(|| {
                let ports = node.output_ports.clone();
                view! {
                    <div class="wf-node-section">
                        {ports.into_iter().map(|p| view! {
                            <div class="wf-port-row">
                                <span class="wf-port-dot wf-port-dot-output" />
                                <span class="wf-port-label">{p.label.clone()}</span>
                                <span class="wf-port-schema">{p.path.clone()}</span>
                            </div>
                        }).collect::<Vec<_>>()}
                    </div>
                }
            })}

            // Jump to block
            <button
                class="wf-trace-jump"
                on:click=move |_| {
                    canvas_state.canvas_side.set(CanvasSide::Front);
                    canvas_state.requested_expansion.set(Some(jump_id.clone()));
                }
            >
                "\u{2192} view block"
            </button>
        </div>
    }
}

/// Renders one edge row — a visual wire plus an inline approval card for Proposed edges.
#[component]
fn MapEdgeRow(edge: WorkflowEdge) -> impl IntoView {
    let edge_class = match edge.state {
        EdgeState::Confirmed => "wf-edge wf-edge-confirmed",
        EdgeState::Proposed => "wf-edge wf-edge-proposed",
        EdgeState::Blocked => "wf-edge wf-edge-blocked",
        EdgeState::Unconnected => "wf-edge wf-edge-unconnected",
    };

    let memex_badge = edge.memex_remembered;
    let is_proposed = edge.state == EdgeState::Proposed;
    let edge_for_card = edge.clone();

    view! {
        <div class=edge_class>
            <div class="wf-edge-line">
                <span class="wf-edge-from">{edge.from_port.label.clone()}</span>
                <span class="wf-edge-arrow">"→"</span>
                <span class="wf-edge-to">{edge.to_port.label.clone()}</span>
                {memex_badge.then(|| view! {
                    <span class="wf-edge-memex">"🧠 remembered"</span>
                })}
            </div>
            {is_proposed.then(move || view! {
                <MapApprovalCard edge=edge_for_card />
            })}
        </div>
    }
}

/// Inline approval card for a Proposed edge — shown when the memex has no pre-approval.
/// The user can allow once, always allow (writes to memex), or deny (agent substitution).
#[component]
fn MapApprovalCard(edge: WorkflowEdge) -> impl IntoView {
    let from_label = edge.from_port.label.clone();
    let from_path = edge.from_port.path.clone();
    let to_label = edge.to_port.label.clone();
    let from_node = edge.from_node_id.clone();
    let to_node = edge.to_node_id.clone();

    // "Always allow" — store memex approval record via Tauri IPC
    let always_allow = {
        let from_node = from_node.clone();
        let to_node = to_node.clone();
        let from_path = from_path.clone();
        move |_| {
            let from_node = from_node.clone();
            let to_node = to_node.clone();
            let from_path = from_path.clone();
            spawn_local(async move {
                let args = serde_json::json!({
                    "from_node_id": from_node,
                    "to_node_id": to_node,
                    "property_path": from_path,
                });
                let _ =
                    bridge::invoke::<serde_json::Value, ()>("store_workflow_approval", &args)
                        .await;
            });
        }
    };

    view! {
        <div class="wf-approval-card">
            <div class="wf-approval-card-title">"Approval required"</div>
            <div class="wf-approval-card-agent">{to_label}</div>
            <div class="wf-approval-card-disclosure">
                <span class="wf-approval-icon">"\u{1f512} "</span>
                <span>{from_label.clone()}</span>
                <span class="wf-approval-path">" — "</span>
                <span>{from_path.clone()}</span>
            </div>
            <div class="wf-approval-card-actions">
                <button class="wf-approval-btn wf-approval-allow">"Allow once"</button>
                <button
                    class="wf-approval-btn wf-approval-always"
                    on:click=always_allow
                >
                    "Always allow \u{1f9e0}"
                </button>
                <button class="wf-approval-btn wf-approval-deny">"Deny"</button>
            </div>
        </div>
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DESIGN MODE
// ─────────────────────────────────────────────────────────────────────────────

/// DESIGN mode — interactive blank canvas for authoring agent pipelines.
#[component]
fn WorkflowDesignMode() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let graph = canvas_state.workflow_graph;

    // New node intent text
    let new_intent: RwSignal<String> = RwSignal::new(String::new());

    let do_add_node = move || {
        let intent = new_intent.get_untracked();
        if intent.trim().is_empty() {
            return;
        }
        let id = format!("design-{}", js_sys::Math::random().to_bits());
        let node = WorkflowNode {
            id,
            node_type: papillon_shared::PipelineNodeType::Agent,
            intent: intent.clone(),
            agent_name: None,
            agent_did: None,
            pap_uri: None,
            action_type: String::new(),
            input_ports: vec![],
            output_ports: vec![],
            template_override: None,
            position_x: 0.0,
            position_y: 0.0,
        };
        graph.update(|g| {
            g.is_designed = true;
            g.nodes.push(node);
        });
        new_intent.set(String::new());
    };
    let add_node = move |_: web_sys::MouseEvent| do_add_node();
    let add_node_keydown = move |e: web_sys::KeyboardEvent| {
        if e.key() == "Enter" {
            do_add_node();
        }
    };

    let run_workflow = move |_| {
        let g = graph.get_untracked();
        if g.nodes.is_empty() {
            return;
        }
        spawn_local(async move {
            let _ =
                bridge::invoke::<serde_json::Value, ()>("run_designed_workflow", &serde_json::json!({
                    "nodes": serde_json::to_value(&g.nodes).unwrap_or_default(),
                    "edges": serde_json::to_value(&g.edges).unwrap_or_default(),
                }))
                .await;
        });
    };

    let save_workflow = move |_| {
        let g = graph.get_untracked();
        spawn_local(async move {
            let _ =
                bridge::invoke::<serde_json::Value, ()>("save_workflow_design", &serde_json::json!({
                    "nodes": serde_json::to_value(&g.nodes).unwrap_or_default(),
                    "edges": serde_json::to_value(&g.edges).unwrap_or_default(),
                }))
                .await;
        });
    };

    let has_nodes = move || !graph.get().nodes.is_empty();

    view! {
        <div class="wf-design-layout">
            // Tools strip
            <div class="wf-design-tools">
                <input
                    class="wf-node-intent-input"
                    type="text"
                    placeholder="Describe what this agent should do…"
                    prop:value=move || new_intent.get()
                    on:input=move |e| new_intent.set(event_target_value(&e))
                    on:keydown=add_node_keydown
                />
                <button
                    class="wf-design-tool-btn wf-design-add"
                    on:click=add_node
                >
                    "+ Add node"
                </button>
                <button
                    class="wf-design-tool-btn wf-design-run"
                    on:click=run_workflow
                    disabled=move || !has_nodes()
                >
                    "▶ Run"
                </button>
                <button
                    class="wf-design-tool-btn wf-design-save"
                    on:click=save_workflow
                    disabled=move || !has_nodes()
                >
                    "Save"
                </button>
            </div>

            // Node list
            <div class="wf-graph-canvas">
                <Show
                    when=has_nodes
                    fallback=|| view! {
                        <div class="wf-graph-empty">
                            <p>"Design canvas is empty."</p>
                            <p class="wf-graph-empty-hint">
                                "Add nodes above to build a multi-agent pipeline."
                            </p>
                        </div>
                    }
                >
                    <div class="wf-graph-row">
                        <For
                            each=move || graph.get().nodes
                            key=|n| n.id.clone()
                            children=move |node| {
                                let nid = node.id.clone();
                                let intent = node.intent.clone();
                                let agent = node.agent_name.clone().unwrap_or_default();
                                view! {
                                    <div class="wf-node">
                                        <div class="wf-node-header">
                                            <span class="wf-node-emoji">"🤖"</span>
                                            <span class="wf-node-name">
                                                {if agent.is_empty() { intent } else { agent }}
                                            </span>
                                        </div>
                                        <button
                                            class="wf-trace-jump"
                                            on:click=move |_| {
                                                let nid = nid.clone();
                                                graph.update(|g| g.nodes.retain(|n| n.id != nid));
                                            }
                                        >
                                            "✕ remove"
                                        </button>
                                    </div>
                                }
                            }
                        />
                    </div>
                </Show>
            </div>
        </div>
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATION TRACE (back-face)
// ─────────────────────────────────────────────────────────────────────────────

/// Derive display properties from a block's current state.
/// Returns (CSS modifier class, badge label, optional inline description text).
pub(crate) fn derive_block_trace(
    block: &CanvasBlock,
) -> (&'static str, &'static str, Option<String>) {
    match &block.state {
        BlockState::Resolving { phase_label, .. } => {
            ("trace-resolving", "resolving", Some(phase_label.clone()))
        }
        BlockState::AwaitingApproval { .. } => ("trace-awaiting", "awaiting approval", None),
        BlockState::Ghost { agent_name, .. } => (
            "trace-ghost",
            "pre-approval",
            Some(format!("Agent: {agent_name}")),
        ),
        BlockState::Resolved => ("trace-resolved", "done", None),
        BlockState::Failed { reason, .. } => ("trace-failed", "failed", Some(reason.clone())),
        BlockState::Outcome { .. } => ("trace-resolved", "outcome", None),
        _ => ("trace-pending", "pending", None),
    }
}

/// Inline approval plan summary — shown inside a `trace-awaiting` entry.
#[component]
pub fn ApprovalPlanInline(plan: IntentPlan) -> impl IntoView {
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
#[component]
pub fn EdgeApprovalCard(
    edge: WorkflowEdge,
    on_allow_once: Callback<()>,
    on_always_allow: Callback<()>,
    on_deny: Callback<()>,
) -> impl IntoView {
    let from_label = edge.from_port.label.clone();
    let from_path = edge.from_port.path.clone();
    let to_label = edge.to_port.label.clone();

    view! {
        <div class="wf-approval-card">
            <div class="wf-approval-agent">
                <span class="wf-approval-icon">"\u{1f916}"</span>
                <div class="wf-approval-agent-info">
                    <span class="wf-approval-agent-name">{to_label}</span>
                </div>
                <span class="wf-tee-badge">"\u{2713} TEE"</span>
            </div>
            <p class="wf-approval-prompt">"This agent will receive:"</p>
            <div class="wf-disclosure-list">
                <div class="wf-disclosure-item">
                    <span class="wf-disclosure-label">{from_label}</span>
                    <span class="wf-disclosure-path">{from_path}</span>
                    <span class="wf-disclosure-check">"\u{2713}"</span>
                </div>
            </div>
            <div class="wf-approval-redacted">
                "\u{1f512} Will not see: your name, email, payment details, or any other data."
            </div>
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
