use leptos::prelude::*;
use papillon_shared::{EdgeState, PipelineNodeType, PortRef, WorkflowEdge, WorkflowMode, WorkflowNode};
use papillon_shared::types::Template;

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

    let nodes = move || workflow.graph.get().nodes;
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
                    <For
                        each=nodes
                        key=|n| n.id.clone()
                        children=move |node| {
                            view! { <MapNode node=node /> }
                        }
                    />
                </div>
            </Show>
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

    let show_approval_demo = RwSignal::new(false);

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
            input_ports: Vec::new(),
            output_ports: Vec::new(),
            template_override: None,
            position_x: nodes.len() as f64 * 260.0,
            position_y: 60.0,
        });
        workflow.design_nodes.set(nodes);
    };

    let run_workflow = move |_| {
        // Flip to front face immediately so user sees blocks appear in real time
        canvas_state.canvas_side.set(CanvasSide::Front);
        // TODO: trigger pipeline execution from design_nodes/design_edges
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
                <button class="wf-tool" title="Save pipeline">
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

            // Approval card demo — shown when a paused edge triggers in Design mode
            <Show when=move || show_approval_demo.get()>
                <EdgeApprovalCard
                    edge=WorkflowEdge {
                        id: "demo".into(),
                        from_node_id: "n1".into(),
                        from_port: PortRef {
                            path: "schema:FlightReservation.departureDate".into(),
                            label: "Departure Date".into(),
                            required: true,
                        },
                        to_node_id: "n2".into(),
                        to_port: PortRef {
                            path: "schema:LodgingReservation.checkInDate".into(),
                            label: "Hotel Search".into(),
                            required: true,
                        },
                        state: EdgeState::Proposed,
                        memex_remembered: false,
                    }
                    on_allow_once=Callback::new(move |_| { show_approval_demo.set(false); })
                    on_always_allow=Callback::new(move |_| { show_approval_demo.set(false); })
                    on_deny=Callback::new(move |_| { show_approval_demo.set(false); })
                />
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
                n.intent = value;
            }
            workflow.design_nodes.set(nodes);
            intent.set(
                workflow
                    .design_nodes
                    .get_untracked()
                    .iter()
                    .find(|n| n.id == node_id)
                    .map(|n| n.intent.clone())
                    .unwrap_or_default(),
            );
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
    if intent.len() > 28 {
        format!("{}…", &intent[..28])
    } else if intent.is_empty() {
        "Block".to_string()
    } else {
        intent.to_string()
    }
}
