use leptos::prelude::*;
use papillon_shared::{
    intent::detect_intent, BlockState, CanvasBlock, EdgeState, IntentPlan, PipelineEdgeInfo,
    PipelineInfo, PipelineNodeInfo, PipelineNodeType, PortRef, WorkflowEdge, WorkflowMode,
    WorkflowNode,
};
use papillon_shared::types::Template;
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::{
    canvas::{CanvasSide, CanvasState},
    workflow::WorkflowState,
};

/// Main workflow canvas component rendered in the back face Workflow tab.
/// Shows MAP mode (auto-derived live dependency graph) or DESIGN mode (intent-first builder).
#[component]
pub fn CanvasWorkflowPipeline() -> impl IntoView {
    let workflow = expect_context::<WorkflowState>();

    view! {
        <div class="wf-canvas">
            <div class="wf-mode-toggle">
                <button
                    class="wf-toggle-btn"
                    class:active=move || workflow.mode.get() == WorkflowMode::Map
                    on:click=move |_| workflow.mode.set(WorkflowMode::Map)
                >
                    "MAP"
                </button>
                <button
                    class="wf-toggle-btn"
                    class:active=move || workflow.mode.get() == WorkflowMode::Design
                    on:click=move |_| workflow.mode.set(WorkflowMode::Design)
                >
                    "DESIGN"
                </button>
            </div>

            <Show when=move || workflow.mode.get() == WorkflowMode::Map>
                <MapModeCanvas />
            </Show>
            <Show when=move || workflow.mode.get() == WorkflowMode::Design>
                <DesignModeCanvas />
            </Show>
        </div>
    }
}

/// Map mode: read-only live dependency graph auto-derived from canvas block events.
#[component]
fn MapModeCanvas() -> impl IntoView {
    let workflow = expect_context::<WorkflowState>();

    let has_nodes = move || !workflow.graph.get().nodes.is_empty();

    view! {
        <div class="wf-map-canvas">
            <Show
                when=has_nodes
                fallback=|| view! {
                    <div class="wf-empty-state">
                        <p class="wf-empty-hint">
                            "Run a prompt to see the dependency graph."
                        </p>
                    </div>
                }
            >
                <div class="wf-graph-row">
                    {move || {
                        let graph = workflow.graph.get();
                        let mut items: Vec<leptos::prelude::AnyView> = Vec::new();
                        for (i, node) in graph.nodes.iter().enumerate() {
                            // Edge connector before each node except the first.
                            if i > 0 {
                                // Find the edge coming into this node (if any).
                                let target_id = node.id.clone();
                                let edge_state = graph.edges.iter()
                                    .find(|e| e.to_node_id == target_id)
                                    .map(|e| e.state.clone())
                                    .unwrap_or(EdgeState::Unconnected);
                                let memex = graph.edges.iter()
                                    .find(|e| e.to_node_id == target_id)
                                    .map(|e| e.memex_remembered)
                                    .unwrap_or(false);
                                items.push(view! { <MapEdgeConnector state=edge_state memex_remembered=memex /> }.into_any());
                            }
                            items.push(view! { <MapNode node=node.clone() /> }.into_any());
                        }
                        items
                    }}
                </div>
            </Show>
        </div>
    }
}

/// A directed edge connector rendered between two Map mode nodes.
/// Uses CSS flexbox alignment — no SVG geometry required.
#[component]
fn MapEdgeConnector(state: EdgeState, memex_remembered: bool) -> impl IntoView {
    let line_class = match state {
        EdgeState::Confirmed => "wf-edge-line",
        EdgeState::Proposed => "wf-edge-line proposed",
        EdgeState::Blocked => "wf-edge-line blocked",
        EdgeState::Unconnected => "wf-edge-line unconnected",
    };
    view! {
        <div class="wf-edge-connector">
            <div class={line_class}></div>
            {memex_remembered.then(|| view! {
                <span class="wf-memex-badge">"🧠"</span>
            })}
        </div>
    }
}

/// A single resolved/running block shown as a node in Map mode.
#[component]
fn MapNode(node: WorkflowNode) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let node_id = node.id.clone();
    let display_name = node
        .agent_name
        .clone()
        .unwrap_or_else(|| truncate_intent(&node.intent));
    let pap_uri = node.pap_uri.clone();

    view! {
        <div
            class="wf-node wf-node-resolved"
            on:click=move |_| {
                canvas_state.canvas_side.set(CanvasSide::Front);
                canvas_state.requested_expansion.set(Some(node_id.clone()));
            }
        >
            <div class="wf-node-header">
                <span class="wf-node-icon">"🤖"</span>
                <span class="wf-node-name">{display_name}</span>
                {pap_uri.map(|u| view! {
                    <span class="wf-node-uri">{u}</span>
                })}
            </div>
        </div>
    }
}

/// Design mode: intent-first workflow builder with tools strip and node graph area.
#[component]
fn DesignModeCanvas() -> impl IntoView {
    let workflow = expect_context::<WorkflowState>();
    let canvas_state = expect_context::<CanvasState>();

    // Reactively find the first canvas block currently in AwaitingApproval state.
    // This drives the inline EdgeApprovalCard — no manual toggle required.
    let blocks = canvas_state.current_canvas_blocks();
    let awaiting_approval: Memo<Option<(String, IntentPlan)>> = Memo::new(move |_| {
        blocks.get().into_iter().find_map(|b| {
            if let BlockState::AwaitingApproval { plan } = b.state {
                Some((b.id, plan))
            } else {
                None
            }
        })
    });

    let add_agent_node = move |_| {
        let mut nodes = workflow.design_nodes.get_untracked();
        let id = format!("node-{}", nodes.len());
        nodes.push(WorkflowNode {
            id,
            node_type: PipelineNodeType::Agent,
            intent: String::new(),
            agent_name: None,
            agent_did: None,
            pap_uri: None,
            action_type: String::new(),
            input_ports: Vec::new(),
            output_ports: Vec::new(),
            template_override: None,
            position_x: nodes.len() as f64 * 260.0,
            position_y: 60.0,
        });
        workflow.design_nodes.set(nodes);
    };

    let run_workflow = move |_| {
        let nodes = workflow.design_nodes.get_untracked();
        let edges = workflow.design_edges.get_untracked();
        if nodes.is_empty() {
            return;
        }

        // Stable pipeline ID for this run so all block IDs are deterministic.
        let pipeline_id = {
            let ts = js_sys::Date::new_0().get_time() as u64;
            format!("wf-{ts}")
        };

        // Resolve the canvas ID — create one if there is none.
        let canvas_id = {
            let existing = canvas_state.current_canvas_id.get_untracked();
            match existing {
                Some(id) => id,
                None => canvas_state.new_canvas(),
            }
        };

        // Build PipelineInfo from design nodes/edges.
        // Block ID pattern must match what run_pipeline emits: "pipeline-{id}-{node_id}".
        let pipeline_nodes: Vec<PipelineNodeInfo> = nodes.iter().map(|n| PipelineNodeInfo {
            id: n.id.clone(),
            agent_hash: String::new(),
            agent_name: n.agent_name.clone().unwrap_or_else(|| n.intent.clone()),
            // Use the node's resolved action_type if available; otherwise derive it
            // from the intent text using the same deterministic routing as the
            // single-block canvas path. This ensures the correct agent is selected
            // even before marketplace resolution populates action_type.
            action_type: if n.action_type.is_empty() {
                detect_intent(&n.intent).0.to_string()
            } else {
                n.action_type.clone()
            },
            node_type: n.node_type.clone(),
            position_x: n.position_x,
            position_y: n.position_y,
            format: papillon_shared::SynthesisFormat::FreeText,
        }).collect();

        let pipeline_edges: Vec<PipelineEdgeInfo> = edges.iter().map(|e| PipelineEdgeInfo {
            from_node: e.from_node_id.clone(),
            to_node: e.to_node_id.clone(),
        }).collect();

        let now = js_sys::Date::new_0().to_iso_string().as_string().unwrap_or_default();
        let pipeline = PipelineInfo {
            id: pipeline_id.clone(),
            name: "Design Canvas Run".to_string(),
            nodes: pipeline_nodes,
            edges: pipeline_edges,
            created_at: now.clone(),
        };

        // Pre-create skeleton Resolving blocks using the canonical "pipeline-{id}-{node_id}"
        // IDs so that block_updated/block_resolved events from the backend land correctly.
        canvas_state.canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                for node in &nodes {
                    let block_id = format!("pipeline-{pipeline_id}-{}", node.id);
                    if !canvas.blocks.iter().any(|b| b.id == block_id) {
                        canvas.blocks.push(CanvasBlock {
                            id: block_id,
                            prompt_id: String::new(),
                            prompt_text: Some(node.intent.clone()),
                            state: BlockState::Resolving {
                                phase: 1,
                                phase_label: "Queued".into(),
                            },
                            schema_type: None,
                            content: None,
                            linked_block_ids: Vec::new(),
                            agent_did: node.agent_did.clone(),
                            mandate_expires_at: None,
                            preference_guided: false,
                            auto_expand: false,
                            retention_warning: None,
                            created_at: now.clone(),
                            updated_at: now.clone(),
                        });
                    }
                }
                canvas.updated_at = now.clone();
            }
        });

        // Flip to front face so user sees the resolving blocks immediately.
        canvas_state.canvas_side.set(CanvasSide::Front);

        // Use the first node's intent as the initial_query seed.
        let initial_query = nodes.first().map(|n| n.intent.clone()).unwrap_or_default();
        let canvas_id_clone = canvas_id.clone();

        spawn_local(async move {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct RunArgs {
                pipeline: PipelineInfo,
                initial_query: String,
                canvas_id: Option<String>,
            }
            let args = RunArgs {
                pipeline,
                initial_query,
                canvas_id: Some(canvas_id_clone),
            };
            let _ = bridge::invoke::<_, serde_json::Value>("run_pipeline", &args).await;
        });
    };

    let has_nodes = move || !workflow.design_nodes.get().is_empty();

    view! {
        <div class="wf-design-canvas">
            // Tools strip
            <div class="wf-tools-strip">
                <button class="wf-tool wf-tool-active" on:click=add_agent_node title="Add agent node">
                    <span>"🤖"</span>
                    <span class="wf-tool-label">"Agent"</span>
                </button>
                <button class="wf-tool" title="Add synthesizer node">
                    <span>"⬡"</span>
                    <span class="wf-tool-label">"Synth"</span>
                </button>
                <button class="wf-tool" title="Add note">
                    <span>"📝"</span>
                    <span class="wf-tool-label">"Note"</span>
                </button>
                <div class="wf-tool-spacer"></div>
                <button class="wf-tool" title="Save pipeline (coming soon)" disabled=true>
                    <span>"💾"</span>
                    <span class="wf-tool-label">"Save"</span>
                </button>
                <button class="wf-tool wf-tool-run" on:click=run_workflow title="Run workflow">
                    <span>"▶"</span>
                    <span class="wf-tool-label">"Run"</span>
                </button>
            </div>

            // Node graph area
            <div class="wf-graph-area">
                <Show
                    when=has_nodes
                    fallback=|| view! {
                        <div class="wf-empty-state">
                            <p class="wf-empty-hint">
                                "Click 🤖 to add an agent step."
                            </p>
                        </div>
                    }
                >
                    <For
                        each=move || workflow.design_nodes.get()
                        key=|n| n.id.clone()
                        children=move |node| {
                            view! { <DesignNode node=node /> }
                        }
                    />
                </Show>
            </div>

            // Inline approval card — surfaced when any canvas block transitions to
            // BlockState::AwaitingApproval during a workflow run. Wired to the real
            // CanvasState approve/reject methods so decisions flow back to the backend.
            <Show when=move || awaiting_approval.get().is_some()>
                {move || {
                    awaiting_approval.get().map(|(block_id, plan)| {
                        let plan_clone = plan.clone();
                        let block_id_allow = block_id.clone();
                        let block_id_deny = block_id.clone();
                        let request_id_allow = plan.approval_request_id.clone();
                        let request_id_deny = plan_clone.approval_request_id.clone();

                        // Build a display edge from the plan's disclosure list.
                        let from_path = plan_clone.requires_disclosure.first()
                            .cloned()
                            .unwrap_or_default();
                        let from_label = from_path.split('.').last()
                            .unwrap_or("output")
                            .to_string();
                        let to_label = plan_clone.selected_agent_name.clone();
                        let edge = WorkflowEdge {
                            id: plan_clone.approval_request_id.clone(),
                            from_node_id: String::new(),
                            from_port: PortRef {
                                path: from_path,
                                label: from_label,
                                required: true,
                            },
                            to_node_id: block_id.clone(),
                            to_port: PortRef {
                                path: plan_clone.action.clone(),
                                label: to_label,
                                required: true,
                            },
                            state: EdgeState::Proposed,
                            memex_remembered: false,
                        };

                        view! {
                            <EdgeApprovalCard
                                edge=edge
                                on_allow_once=Callback::new(move |_| {
                                    canvas_state.approve_block(
                                        block_id_allow.clone(),
                                        request_id_allow.clone(),
                                    );
                                })
                                on_always_allow=Callback::new(move |_| {
                                    // store_approval_record is called by the front-face approval
                                    // flow; here we just forward to approve_block so the workflow
                                    // resumes — the backend writes the memex record on its side.
                                    canvas_state.approve_block(
                                        block_id.clone(),
                                        plan.approval_request_id.clone(),
                                    );
                                })
                                on_deny=Callback::new(move |_| {
                                    canvas_state.reject_block(
                                        block_id_deny.clone(),
                                        request_id_deny.clone(),
                                    );
                                })
                            />
                        }
                    })
                }}
            </Show>
        </div>
    }
}

/// A node in Design mode — shows intent input, input/output ports, and template picker.
#[component]
fn DesignNode(node: WorkflowNode) -> impl IntoView {
    let workflow = expect_context::<WorkflowState>();
    let node_id = node.id.clone();
    let intent = RwSignal::new(node.intent.clone());

    let on_intent_input = {
        let node_id = node_id.clone();
        move |ev: leptos::ev::Event| {
            let value = event_target_value(&ev);
            let mut nodes = workflow.design_nodes.get_untracked();
            if let Some(n) = nodes.iter_mut().find(|n| n.id == node_id) {
                n.intent = value.clone();
            }
            workflow.design_nodes.set(nodes);
            // Sync local display signal directly from the value already in hand —
            // no need to re-read design_nodes.
            intent.set(value);
        }
    };

    let display_name = node
        .agent_name
        .clone()
        .unwrap_or_else(|| "New Agent".to_string());

    let input_ports = node.input_ports.clone();
    let output_ports = node.output_ports.clone();

    // Extract schema type from the first output port path:
    // "schema:FlightReservation.departureDate" -> "FlightReservation"
    let returns_schema_type = node.output_ports.first().map(|p| {
        p.path
            .split(':')
            .nth(1)
            .and_then(|s| s.split('.').next())
            .unwrap_or("")
            .to_string()
    }).filter(|s| !s.is_empty());

    // Each design node tracks its own template override
    let template_override = RwSignal::new(node.template_override.clone());

    view! {
        <div class="wf-node wf-node-pending">
            <div class="wf-node-header">
                <span class="wf-node-icon">"🤖"</span>
                <span class="wf-node-name">{display_name}</span>
            </div>

            // RECEIVES FROM PRINCIPAL section
            <div class="wf-node-section">
                <div class="wf-node-section-label">"RECEIVES FROM PRINCIPAL"</div>
                {if input_ports.is_empty() {
                    view! { <div class="wf-port-empty">"—"</div> }.into_any()
                } else {
                    view! {
                        <For
                            each=move || input_ports.clone()
                            key=|p| p.path.clone()
                            children=|port| view! {
                                <div class="wf-port-row input">
                                    <span class="wf-port-dot"></span>
                                    <span class="wf-port-label">{port.label.clone()}</span>
                                </div>
                            }
                        />
                    }.into_any()
                }}
            </div>

            // OUTPUTS section
            <div class="wf-node-section">
                <div class="wf-node-section-label">"OUTPUTS"</div>
                {if output_ports.is_empty() {
                    view! { <div class="wf-port-empty">"—"</div> }.into_any()
                } else {
                    view! {
                        <For
                            each=move || output_ports.clone()
                            key=|p| p.path.clone()
                            children=|port| view! {
                                <div class="wf-port-row output">
                                    <span class="wf-port-label">{port.label.clone()}</span>
                                    <span class="wf-port-dot"></span>
                                </div>
                            }
                        />
                    }.into_any()
                }}
            </div>

            // Intent input (visible before agent resolves)
            <div class="wf-node-section">
                <input
                    type="text"
                    class="wf-node-intent-input"
                    placeholder="What should this step do?"
                    prop:value=intent
                    on:input=on_intent_input
                />
            </div>

            // RENDER AS — live template picker filtered by node's output schema type
            <NodeTemplatePicker
                returns_schema_type=returns_schema_type
                current_override=template_override
            />
        </div>
    }
}

/// Template picker for a Design mode node.
/// Loads templates from the backend filtered by the node's returns schema type.
/// Only shows templates compatible with the agent's output type.
#[component]
fn NodeTemplatePicker(
    /// The schema type of what this node returns (from agent advertisement.returns[0]).
    /// None means the output type is not yet known; the picker shows only "auto".
    returns_schema_type: Option<String>,
    /// Currently selected template name override (None = auto)
    current_override: RwSignal<Option<String>>,
) -> impl IntoView {
    let schema_type = returns_schema_type.clone();

    // Load templates from the backend filtered by schema_type.
    // LocalResource re-runs whenever schema_type changes (it is captured by value).
    let templates = LocalResource::new(move || {
        let stype = schema_type.clone();
        async move {
            match stype {
                Some(st) if !st.is_empty() => {
                    bridge::invoke::<serde_json::Value, Vec<Template>>(
                        "get_templates_for_type",
                        &serde_json::json!({ "schema_type": st }),
                    )
                    .await
                    .unwrap_or_default()
                }
                _ => Vec::<Template>::new(),
            }
        }
    });

    view! {
        <div class="wf-node-template-picker">
            <span class="wf-node-template-label">"RENDER AS"</span>
            <select
                class="wf-node-template-select"
                on:change=move |ev| {
                    let val = event_target_value(&ev);
                    if val == "auto" {
                        current_override.set(None);
                    } else {
                        current_override.set(Some(val));
                    }
                }
            >
                <option value="auto">"auto"</option>
                <Suspense>
                    {move || templates.get().map(|ts| {
                        ts.iter().map(|t| {
                            let name = t.template_name.clone();
                            let name_display = name.clone();
                            let selected = current_override.get().as_deref() == Some(name.as_str());
                            view! {
                                <option value=name selected=selected>
                                    {name_display}
                                </option>
                            }
                        }).collect::<Vec<_>>()
                    })}
                </Suspense>
            </select>
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
                <span class="wf-approval-icon">"🤖"</span>
                <div class="wf-approval-agent-info">
                    <span class="wf-approval-agent-name">{to_label}</span>
                </div>
                <span class="wf-tee-badge">"✓ TEE"</span>
            </div>

            // Plain English disclosure description
            <p class="wf-approval-prompt">"This agent will receive:"</p>
            <div class="wf-disclosure-list">
                <div class="wf-disclosure-item">
                    <span class="wf-disclosure-label">{from_label}</span>
                    <span class="wf-disclosure-path">{from_path}</span>
                    <span class="wf-disclosure-check">"✓"</span>
                </div>
            </div>

            // What the agent will NOT see
            <div class="wf-approval-redacted">
                "🔒 Will not see: your name, email, payment details, or any other data."
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
                    "Always allow 🧠"
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

fn truncate_intent(intent: &str) -> String {
    const MAX_CHARS: usize = 28;
    if intent.is_empty() {
        return "Block".to_string();
    }
    let char_count = intent.chars().count();
    if char_count > MAX_CHARS {
        // Collect exactly MAX_CHARS characters so we never split a multi-byte codepoint.
        let truncated: String = intent.chars().take(MAX_CHARS).collect();
        format!("{truncated}…")
    } else {
        intent.to_string()
    }
}
