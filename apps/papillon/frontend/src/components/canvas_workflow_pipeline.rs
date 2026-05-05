use std::collections::{BTreeMap, BTreeSet};

use leptos::prelude::*;
use papillon_shared::{
    BlockState, CanvasBlock, IntentPlan, PipelineNodeType, WorkflowEdge, WorkflowGraph,
    WorkflowNode,
};

use crate::state::canvas::CanvasState;
use crate::workflow_labels::{
    humanize_reason, humanize_schema_term, render_label_for_schema,
    user_visible_schema_type_label,
};

const NODE_WIDTH: f64 = 248.0;
const NODE_HEIGHT: f64 = 152.0;
const COLUMN_GAP: f64 = 312.0;
const ROW_GAP: f64 = 196.0;
const BOARD_PADDING_X: f64 = 56.0;
const BOARD_PADDING_Y: f64 = 56.0;

#[derive(Clone, PartialEq)]
struct WorkflowMapView {
    nodes: Vec<WorkflowMapNode>,
    edges: Vec<WorkflowMapEdge>,
    width: f64,
    height: f64,
}

#[derive(Clone, PartialEq)]
struct WorkflowMapNode {
    graph_node: WorkflowNode,
    block: CanvasBlock,
    x: f64,
    y: f64,
    incoming: usize,
    outgoing: usize,
}

#[derive(Clone, PartialEq)]
struct WorkflowMapEdge {
    edge: WorkflowEdge,
    path: String,
    hitbox_x: f64,
    hitbox_y: f64,
    hitbox_width: f64,
    hitbox_height: f64,
}

#[derive(Clone, Copy)]
struct WorkflowSurfaceContext {
    canvas: CanvasState,
    graph: Memo<WorkflowGraph>,
    blocks: Memo<Vec<CanvasBlock>>,
    map_view: Memo<WorkflowMapView>,
    selected_node_id: RwSignal<Option<String>>,
    selected_edge_id: RwSignal<Option<String>>,
    selected_block: Memo<Option<CanvasBlock>>,
    selected_edge: Memo<Option<WorkflowEdge>>,
}

#[derive(Clone, PartialEq)]
struct WorkflowNodeRefContext {
    node_id: String,
}

#[derive(Clone, PartialEq)]
struct WorkflowEdgeRefContext {
    edge_id: String,
}

#[derive(Clone)]
struct WorkflowSelectedBlockContext {
    detail: Memo<Option<WorkflowBlockDetailContext>>,
}

#[derive(Clone)]
struct WorkflowSelectedEdgeContext {
    detail: Memo<Option<WorkflowEdgeDetailContext>>,
}

#[derive(Clone, PartialEq)]
struct WorkflowBlockDetailContext {
    block: CanvasBlock,
    title: String,
    source: String,
    artifact: String,
    intent: Option<String>,
    summary: String,
    disclosures: Vec<String>,
    returns: Vec<String>,
    permission_window: Option<String>,
    technical_state: &'static str,
    linked: Vec<String>,
    schema_type: Option<String>,
    agent_did: Option<String>,
    technical_action: Option<String>,
    upstream: Vec<(String, String)>,
    downstream: Vec<(String, String)>,
    can_insert_ref: bool,
    can_retry: bool,
    plan: Option<IntentPlan>,
    detail_state_label: String,
    needs_empty_copy: bool,
}

#[derive(Clone, PartialEq)]
struct WorkflowEdgeDetailContext {
    edge: WorkflowEdge,
    source_title: String,
    target_title: String,
    relationship: String,
    source_block: Option<CanvasBlock>,
}

impl WorkflowSurfaceContext {
    fn clear_selection(&self) {
        self.selected_node_id.set(None);
        self.selected_edge_id.set(None);
    }

    fn focus_node(&self, node_id: String) {
        self.selected_edge_id.set(None);
        self.selected_node_id.set(Some(node_id));
    }

    fn focus_edge(&self, edge_id: String) {
        self.selected_node_id.set(None);
        self.selected_edge_id.set(Some(edge_id));
    }

    fn node_by_id(&self, node_id: &str) -> Option<WorkflowMapNode> {
        self.map_view
            .get()
            .nodes
            .into_iter()
            .find(|node| node.block.id == node_id)
    }

    fn edge_by_id(&self, edge_id: &str) -> Option<WorkflowMapEdge> {
        self.map_view
            .get()
            .edges
            .into_iter()
            .find(|edge| edge.edge.id == edge_id)
    }
}

#[component]
pub fn CanvasWorkflowPipeline() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let selected_node_id: RwSignal<Option<String>> = RwSignal::new(None);
    let selected_edge_id: RwSignal<Option<String>> = RwSignal::new(None);
    let active_blocks = canvas_state.current_canvas_blocks();

    let graph = Memo::new(move |_| canvas_state.workflow_graph.get());
    let workflow_blocks = Memo::new(move |_| {
        active_blocks
            .get()
            .into_iter()
            .filter(|block| !matches!(block.state, BlockState::Guide { .. }))
            .collect::<Vec<_>>()
    });
    let map_view = Memo::new(move |_| build_workflow_map(&graph.get(), &workflow_blocks.get()));
    let selected_block = Memo::new(move |_| {
        let selected_id = selected_node_id.get()?;
        workflow_blocks
            .get()
            .into_iter()
            .find(|block| block.id == selected_id)
    });
    let selected_edge = Memo::new(move |_| {
        let selected_id = selected_edge_id.get()?;
        graph.get().edges.into_iter().find(|edge| edge.id == selected_id)
    });

    Effect::new(move || {
        let node_ids = map_view
            .get()
            .nodes
            .into_iter()
            .map(|node| node.block.id)
            .collect::<BTreeSet<_>>();
        if selected_node_id
            .get()
            .as_ref()
            .is_some_and(|id| !node_ids.contains(id))
        {
            selected_node_id.set(None);
        }

        let edge_ids = map_view
            .get()
            .edges
            .into_iter()
            .map(|edge| edge.edge.id)
            .collect::<BTreeSet<_>>();
        if selected_edge_id
            .get()
            .as_ref()
            .is_some_and(|id| !edge_ids.contains(id))
        {
            selected_edge_id.set(None);
        }
    });

    provide_context(WorkflowSurfaceContext {
        canvas: canvas_state,
        graph,
        blocks: workflow_blocks,
        map_view,
        selected_node_id,
        selected_edge_id,
        selected_block,
        selected_edge,
    });

    view! {
        <div class="wf-panel wf-map-panel">
            <div class="wf-map-shell">
                <WorkflowHero />
                <WorkflowBoardRegion />
                <WorkflowSelectionPanel />
            </div>
        </div>
    }
}

#[component]
fn WorkflowHero() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();

    view! {
        <div class="wf-map-hero">
            <div class="wf-map-kicker">"Workflow"</div>
            <h3 class="wf-map-title">
                "Follow what Papillon is sharing, resolving, and turning into something you can use."
            </h3>
            <p class="wf-map-copy">
                {move || workflow_summary(&workflow.blocks.get(), &workflow.graph.get())}
            </p>
        </div>
    }
}

#[component]
fn WorkflowBoardRegion() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();

    view! {
        <Show
            when=move || !workflow.map_view.get().nodes.is_empty()
            fallback=move || view! {
                <div class="wf-map-empty">
                    <div class="wf-map-empty-title">"This side fills in after the first real step."</div>
                    <p class="wf-map-empty-copy">
                        "Use the top bar to browse, ask, or reference an existing block. Papillon will map the relationships here as it works."
                    </p>
                </div>
            }
        >
            <WorkflowBoard />
        </Show>
    }
}

#[component]
fn WorkflowBoard() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();

    view! {
        <div class="wf-map-board-shell">
            <div class="wf-map-board" on:click=move |_| workflow.clear_selection()>
                <div
                    class="wf-map-board-canvas"
                    style=move || {
                        let map = workflow.map_view.get();
                        format!(
                            "width: {:.0}px; height: {:.0}px;",
                            map.width.max(840.0),
                            map.height.max(420.0)
                        )
                    }
                >
                    <svg
                        class="wf-map-edges"
                        viewBox=move || {
                            let map = workflow.map_view.get();
                            format!(
                                "0 0 {:.0} {:.0}",
                                map.width.max(840.0),
                                map.height.max(420.0)
                            )
                        }
                        preserveAspectRatio="none"
                    >
                        <For
                            each=move || workflow.map_view.get().edges
                            key=|edge| edge.edge.id.clone()
                            children=move |edge| view! { <WorkflowEdgeScope edge=edge /> }
                        />
                    </svg>

                    <For
                        each=move || workflow.map_view.get().nodes
                        key=|node| node.block.id.clone()
                        children=move |node| view! { <WorkflowNodeScope node=node /> }
                    />
                </div>
            </div>
        </div>
    }
}

#[component]
fn WorkflowEdgeScope(edge: WorkflowMapEdge) -> impl IntoView {
    provide_context(WorkflowEdgeRefContext {
        edge_id: edge.edge.id,
    });
    view! { <WorkflowEdgePath /> }
}

#[component]
fn WorkflowEdgePath() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let edge_ref = expect_context::<WorkflowEdgeRefContext>();
    let edge_id = edge_ref.edge_id.clone();
    let edge = Memo::new(move |_| workflow.edge_by_id(&edge_id));

    view! {
        <Show when=move || edge.get().is_some()>
            <g>
                <rect
                    class="wf-map-edge"
                    x=move || edge.get().map(|current| current.hitbox_x).unwrap_or_default()
                    y=move || edge.get().map(|current| current.hitbox_y).unwrap_or_default()
                    width=move || {
                        edge.get()
                            .map(|current| current.hitbox_width)
                            .unwrap_or_default()
                    }
                    height=move || {
                        edge.get()
                            .map(|current| current.hitbox_height)
                            .unwrap_or_default()
                    }
                    rx="12"
                    on:click=move |event| {
                        event.stop_propagation();
                        if let Some(current_edge) = edge.get() {
                            workflow.focus_edge(current_edge.edge.id);
                        }
                    }
                />
                <path
                    class=move || {
                        let Some(current_edge) = edge.get() else {
                            return String::new();
                        };
                        let mut class_name = format!(
                            "wf-map-edge-visual {}",
                            workflow_edge_class(&current_edge.edge)
                        );
                        if workflow.selected_edge_id.get() == Some(current_edge.edge.id.clone()) {
                            class_name.push_str(" is-selected");
                        }
                        class_name
                    }
                    d=move || edge.get().map(|current| current.path).unwrap_or_default()
                />
            </g>
        </Show>
    }
}

#[component]
fn WorkflowNodeScope(node: WorkflowMapNode) -> impl IntoView {
    provide_context(WorkflowNodeRefContext {
        node_id: node.block.id,
    });
    view! { <WorkflowNodeCard /> }
}

#[component]
fn WorkflowNodeCard() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let node_ref = expect_context::<WorkflowNodeRefContext>();
    let node_id = node_ref.node_id.clone();
    let node = Memo::new(move |_| workflow.node_by_id(&node_id));

    view! {
        <Show when=move || node.get().is_some()>
            <button
                type="button"
                class=move || {
                    let Some(current_node) = node.get() else {
                        return String::new();
                    };
                    let mut class_name = String::from("wf-map-node");
                    class_name.push(' ');
                    class_name.push_str(workflow_state_class(&current_node.block.state));
                    if workflow.selected_node_id.get() == Some(current_node.block.id.clone()) {
                        class_name.push_str(" is-selected");
                    }
                    class_name
                }
                data-block-id=move || node.get().map(|current| current.block.id).unwrap_or_default()
                data-block-state=move || {
                    node.get()
                        .map(|current| workflow_state_label(&current.block.state).to_string())
                        .unwrap_or_default()
                }
                style=move || {
                    node.get()
                        .map(|current| format!("left: {:.0}px; top: {:.0}px;", current.x, current.y))
                        .unwrap_or_default()
                }
                on:click=move |event| {
                    event.stop_propagation();
                    if let Some(current_node) = node.get() {
                        workflow.focus_node(current_node.block.id);
                    }
                }
            >
                <div class="wf-map-node-top">
                    <span class="wf-map-node-state">
                        {move || {
                            node.get()
                                .map(|current| workflow_state_label(&current.block.state).to_string())
                                .unwrap_or_default()
                        }}
                    </span>
                    <Show when=move || {
                        node.get().is_some_and(|current| {
                            matches!(current.graph_node.node_type, PipelineNodeType::Synthesizer)
                        })
                    }>
                        <span class="wf-map-node-kind">"Local result"</span>
                    </Show>
                </div>
                <div class="wf-map-node-source">
                    {move || {
                        node.get()
                            .map(|current| {
                                block_source_label(&current.block, Some(&current.graph_node))
                            })
                            .unwrap_or_default()
                    }}
                </div>
                <div class="wf-map-node-title">
                    {move || {
                        node.get()
                            .map(|current| block_title(&current.block))
                            .unwrap_or_default()
                    }}
                </div>
                <Show when=move || {
                    node.get()
                        .and_then(|current| {
                            let title = block_title(&current.block);
                            block_intent_line(&current.block, &title)
                        })
                        .is_some()
                }>
                    <div class="wf-map-node-intent">
                        {move || {
                            node.get()
                                .and_then(|current| {
                                    let title = block_title(&current.block);
                                    block_intent_line(&current.block, &title)
                                })
                                .unwrap_or_default()
                        }}
                    </div>
                </Show>
                <div class="wf-map-node-artifact">
                    {move || {
                        node.get()
                            .map(|current| render_artifact_label(&current.block))
                            .unwrap_or_default()
                    }}
                </div>
                <div class="wf-map-node-summary">
                    {move || {
                        node.get()
                            .map(|current| {
                                node_summary(
                                    &current.block,
                                    current.incoming,
                                    current.outgoing,
                                )
                            })
                            .unwrap_or_default()
                    }}
                </div>
            </button>
        </Show>
    }
}

#[component]
fn WorkflowSelectionPanel() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();

    view! {
        <Show when=move || workflow.selected_block.get().is_some()>
            <SelectedWorkflowBlock />
        </Show>
        <Show when=move || workflow.selected_edge.get().is_some()>
            <SelectedWorkflowEdge />
        </Show>
    }
}

#[component]
fn SelectedWorkflowBlock() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = Memo::new(move |_| {
        workflow
            .selected_block
            .get()
            .map(|block| block_detail_context(&workflow, block))
    });
    provide_context(WorkflowSelectedBlockContext { detail });
    view! { <WorkflowBlockDetail /> }.into_any()
}

#[component]
fn WorkflowBlockDetail() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;
    view! {
        <Show when=move || detail.get().is_some()>
            <section class="wf-detail-tray">
                <div class="wf-detail-header">
                    <div>
                        <div class="wf-detail-kicker">
                            {move || {
                                detail
                                    .get()
                                    .map(|current| current.detail_state_label)
                                    .unwrap_or_default()
                            }}
                        </div>
                        <h3 class="wf-detail-title">
                            {move || detail.get().map(|current| current.title).unwrap_or_default()}
                        </h3>
                        <p class="wf-detail-copy">
                            {move || {
                                detail
                                    .get()
                                    .map(|current| {
                                        format!(
                                            "{} · {}. {}",
                                            current.source, current.artifact, current.summary
                                        )
                                    })
                                    .unwrap_or_default()
                            }}
                        </p>
                    </div>
                    <button
                        class="wf-detail-close"
                        type="button"
                        on:click=move |_| workflow.clear_selection()
                    >
                        "Close"
                    </button>
                </div>
                <WorkflowBlockDetailBody />
                <WorkflowBlockActions />
                <WorkflowBlockTechnicalDetail />
            </section>
        </Show>
    }
}

#[component]
fn WorkflowBlockDetailBody() -> impl IntoView {
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;

    view! {
        <div class="wf-detail-grid">
            <Show when=move || detail.get().is_some_and(|current| current.intent.is_some())>
                <div class="wf-detail-section">
                    <div class="wf-detail-label">"Asked for"</div>
                    <div class="wf-detail-note">
                        {move || {
                            detail
                                .get()
                                .and_then(|current| current.intent)
                                .unwrap_or_default()
                        }}
                    </div>
                </div>
            </Show>
            <WorkflowBlockShareSection />
            <WorkflowBlockReturnSection />
            <Show when=move || {
                detail
                    .get()
                    .is_some_and(|current| current.permission_window.is_some())
            }>
                <div class="wf-detail-section">
                    <div class="wf-detail-label">"Permission window"</div>
                    <div class="wf-detail-note">
                        {move || {
                            detail
                                .get()
                                .and_then(|current| current.permission_window)
                                .unwrap_or_default()
                        }}
                    </div>
                </div>
            </Show>
            <WorkflowBlockRelationsSection direction="upstream" />
            <WorkflowBlockRelationsSection direction="downstream" />
        </div>
    }
}

#[component]
fn WorkflowBlockShareSection() -> impl IntoView {
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;

    view! {
        <Show
            when=move || detail.get().is_some_and(|current| !current.disclosures.is_empty())
            fallback=move || {
                if detail
                    .get()
                    .is_some_and(|current| current.needs_empty_copy)
                {
                    view! {
                        <div class="wf-detail-section">
                            <div class="wf-detail-label">"Needs from you"</div>
                            <div class="wf-detail-note">"No extra personal data is needed for this step."</div>
                        </div>
                    }
                    .into_any()
                } else {
                    view! { <></> }.into_any()
                }
            }
        >
            <div class="wf-detail-section">
                <div class="wf-detail-label">"Needs from you"</div>
                <div class="wf-detail-pill-list">
                    {move || {
                        detail
                            .get()
                            .map(|current| {
                                current
                                    .disclosures
                                    .iter()
                                    .map(|item| {
                                        let label = humanize_schema_term(item);
                                        view! {
                                            <span class="wf-detail-pill wf-detail-pill-share">{label}</span>
                                        }
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    }}
                </div>
            </div>
        </Show>
    }
}

#[component]
fn WorkflowBlockReturnSection() -> impl IntoView {
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;

    view! {
        <Show when=move || detail.get().is_some_and(|current| !current.returns.is_empty())>
            <div class="wf-detail-section">
                <div class="wf-detail-label">"Likely result"</div>
                <div class="wf-detail-pill-list">
                    {move || {
                        detail
                            .get()
                            .map(|current| {
                                current
                                    .returns
                                    .iter()
                                    .map(|item| {
                                        let label = describe_output_item(item);
                                        view! {
                                            <span class="wf-detail-pill wf-detail-pill-return">{label}</span>
                                        }
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    }}
                </div>
            </div>
        </Show>
    }
}

#[component]
fn WorkflowBlockRelationsSection(direction: &'static str) -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;
    let label = if direction == "upstream" { "Uses" } else { "Feeds" };

    view! {
        <Show when=move || {
            detail.get().is_some_and(|current| {
                let relations = if direction == "upstream" {
                    &current.upstream
                } else {
                    &current.downstream
                };
                !relations.is_empty()
            })
        }>
            <div class="wf-detail-section">
                <div class="wf-detail-label">{label}</div>
                <div class="wf-detail-link-list">
                    {move || {
                        detail
                            .get()
                            .map(|current| {
                                let relations = if direction == "upstream" {
                                    current.upstream
                                } else {
                                    current.downstream
                                };
                                relations
                                    .iter()
                                    .map(|(id, text)| {
                                        let id = id.clone();
                                        let text = text.clone();
                                        view! {
                                            <button
                                                class="wf-detail-link-chip"
                                                type="button"
                                                on:click=move |_| workflow.focus_node(id.clone())
                                            >
                                                {text}
                                            </button>
                                        }
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default()
                    }}
                </div>
            </div>
        </Show>
    }
}

#[component]
fn WorkflowBlockActions() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;

    view! {
        <div class="wf-detail-actions">
            <button
                class="wf-detail-btn wf-detail-btn-primary"
                type="button"
                on:click=move |_| {
                    if let Some(current) = detail.get() {
                        workflow.canvas.expand_block(current.block.id);
                    }
                }
            >
                "Open block"
            </button>

            <Show when=move || detail.get().is_some_and(|current| current.can_insert_ref)>
                <button
                    class="wf-detail-btn"
                    type="button"
                    on:click=move |_| {
                        if let Some(current) = detail.get() {
                            workflow.canvas.insert_block_ref(current.block.id);
                        }
                    }
                >
                    "Use in next step"
                </button>
            </Show>

            <Show when=move || detail.get().is_some_and(|current| current.can_retry)>
                <button
                    class="wf-detail-btn"
                    type="button"
                    on:click=move |_| {
                        if let Some(current) = detail.get() {
                            workflow.canvas.retry_block(current.block.id);
                        }
                    }
                >
                    "Try again"
                </button>
            </Show>

            <Show when=move || detail.get().is_some_and(|current| current.plan.is_some())>
                {move || {
                    let Some(current) = detail.get() else {
                        return view! { <></> }.into_any();
                    };
                    let Some(plan) = current.plan.clone() else {
                        return view! { <></> }.into_any();
                    };
                    let approve_label = if plan.requires_disclosure.is_empty() {
                        "Allow"
                    } else {
                        "Share and run"
                    };
                    let approval_request_id = plan.approval_request_id.clone();
                    let approval_request_id_reject = approval_request_id.clone();
                    let approve_block_id = current.block.id.clone();
                    let reject_block_id = current.block.id.clone();
                    view! {
                        <>
                            <button
                                class="wf-detail-btn wf-detail-btn-allow"
                                type="button"
                                on:click=move |_| {
                                    workflow.canvas.approve_block(
                                        approve_block_id.clone(),
                                        approval_request_id.clone(),
                                        std::collections::HashMap::new(),
                                        Vec::new(),
                                    );
                                }
                            >
                                {approve_label}
                            </button>
                            <button
                                class="wf-detail-btn wf-detail-btn-deny"
                                type="button"
                                on:click=move |_| {
                                    workflow.canvas.reject_block(
                                        reject_block_id.clone(),
                                        approval_request_id_reject.clone(),
                                    );
                                }
                            >
                                "Deny"
                            </button>
                        </>
                    }
                        .into_any()
                }}
            </Show>
        </div>
    }
}

#[component]
fn WorkflowBlockTechnicalDetail() -> impl IntoView {
    let detail = expect_context::<WorkflowSelectedBlockContext>().detail;

    view! {
        <details class="wf-detail-technical">
            <summary>"Technical detail"</summary>
            <div class="wf-detail-technical-list">
                <div class="wf-detail-technical-row">
                    <span class="wf-detail-technical-key">"Block id"</span>
                    <code class="wf-detail-technical-value">
                        {move || detail.get().map(|current| current.block.id).unwrap_or_default()}
                    </code>
                </div>
                <div class="wf-detail-technical-row">
                    <span class="wf-detail-technical-key">"State"</span>
                    <code class="wf-detail-technical-value">
                        {move || {
                            detail
                                .get()
                                .map(|current| current.technical_state.to_string())
                                .unwrap_or_default()
                        }}
                    </code>
                </div>
                <Show when=move || detail.get().is_some_and(|current| current.schema_type.is_some())>
                    <div class="wf-detail-technical-row">
                        <span class="wf-detail-technical-key">"Schema type"</span>
                        <code class="wf-detail-technical-value">
                            {move || {
                                detail
                                    .get()
                                    .and_then(|current| current.schema_type)
                                    .unwrap_or_default()
                            }}
                        </code>
                    </div>
                </Show>
                <Show
                    when=move || detail.get().is_some_and(|current| current.technical_action.is_some())
                >
                    <div class="wf-detail-technical-row">
                        <span class="wf-detail-technical-key">"Action"</span>
                        <code class="wf-detail-technical-value">
                            {move || {
                                detail
                                    .get()
                                    .and_then(|current| current.technical_action)
                                    .unwrap_or_default()
                            }}
                        </code>
                    </div>
                </Show>
                <Show when=move || detail.get().is_some_and(|current| current.agent_did.is_some())>
                    <div class="wf-detail-technical-row">
                        <span class="wf-detail-technical-key">"Agent DID"</span>
                        <code class="wf-detail-technical-value">
                            {move || {
                                detail
                                    .get()
                                    .and_then(|current| current.agent_did)
                                    .unwrap_or_default()
                            }}
                        </code>
                    </div>
                </Show>
                <Show when=move || detail.get().is_some_and(|current| !current.linked.is_empty())>
                    <div class="wf-detail-technical-row">
                        <span class="wf-detail-technical-key">"Linked blocks"</span>
                        <code class="wf-detail-technical-value">
                            {move || {
                                detail
                                    .get()
                                    .map(|current| current.linked.join(", "))
                                    .unwrap_or_default()
                            }}
                        </code>
                    </div>
                </Show>
            </div>
        </details>
    }
}

#[component]
fn SelectedWorkflowEdge() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = Memo::new(move |_| {
        workflow
            .selected_edge
            .get()
            .map(|edge| edge_detail_context(&workflow, edge))
    });
    provide_context(WorkflowSelectedEdgeContext { detail });
    view! { <WorkflowEdgeDetail /> }.into_any()
}

#[component]
fn WorkflowEdgeDetail() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedEdgeContext>().detail;

    view! {
        <Show when=move || detail.get().is_some()>
            <section class="wf-detail-tray">
                <div class="wf-detail-header">
                    <div>
                        <div class="wf-detail-kicker">"Relationship"</div>
                        <h3 class="wf-detail-title">
                            {move || {
                                detail
                                    .get()
                                    .map(|current| {
                                        format!(
                                            "{} to {}",
                                            current.source_title, current.target_title
                                        )
                                    })
                                    .unwrap_or_default()
                            }}
                        </h3>
                        <p class="wf-detail-copy">
                            {move || {
                                detail
                                    .get()
                                    .map(|current| current.relationship)
                                    .unwrap_or_default()
                            }}
                        </p>
                    </div>
                    <button
                        class="wf-detail-close"
                        type="button"
                        on:click=move |_| workflow.clear_selection()
                    >
                        "Close"
                    </button>
                </div>

                <WorkflowEdgeDetailBody />
                <WorkflowEdgeActions />
                <WorkflowEdgeTechnicalDetail />
            </section>
        </Show>
    }
}

#[component]
fn WorkflowEdgeDetailBody() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedEdgeContext>().detail;

    view! {
        <div class="wf-detail-grid">
            <div class="wf-detail-section">
                <div class="wf-detail-label">"From"</div>
                <div class="wf-detail-link-list">
                    <button
                        class="wf-detail-link-chip"
                        type="button"
                        on:click=move |_| {
                            if let Some(current) = detail.get() {
                                workflow.focus_node(current.edge.from_node_id);
                            }
                        }
                    >
                        {move || {
                            detail
                                .get()
                                .map(|current| current.source_title)
                                .unwrap_or_default()
                        }}
                    </button>
                </div>
            </div>

            <div class="wf-detail-section">
                <div class="wf-detail-label">"To"</div>
                <div class="wf-detail-link-list">
                    <button
                        class="wf-detail-link-chip"
                        type="button"
                        on:click=move |_| {
                            if let Some(current) = detail.get() {
                                workflow.focus_node(current.edge.to_node_id);
                            }
                        }
                    >
                        {move || {
                            detail
                                .get()
                                .map(|current| current.target_title)
                                .unwrap_or_default()
                        }}
                    </button>
                </div>
            </div>

            <Show when=move || {
                detail.get().is_some_and(|current| {
                    !current.edge.from_port.label.is_empty() || !current.edge.to_port.label.is_empty()
                })
            }>
                <div class="wf-detail-section">
                    <div class="wf-detail-label">"How Papillon linked them"</div>
                    <div class="wf-detail-pill-list">
                        <Show when=move || {
                            detail
                                .get()
                                .is_some_and(|current| !current.edge.from_port.label.is_empty())
                        }>
                            <span class="wf-detail-pill wf-detail-pill-share">
                                {move || {
                                    detail
                                        .get()
                                        .map(|current| current.edge.from_port.label)
                                        .unwrap_or_default()
                                }}
                            </span>
                        </Show>
                        <Show when=move || {
                            detail
                                .get()
                                .is_some_and(|current| !current.edge.to_port.label.is_empty())
                        }>
                            <span class="wf-detail-pill wf-detail-pill-return">
                                {move || {
                                    detail
                                        .get()
                                        .map(|current| current.edge.to_port.label)
                                        .unwrap_or_default()
                                }}
                            </span>
                        </Show>
                    </div>
                </div>
            </Show>
        </div>
    }
}

#[component]
fn WorkflowEdgeActions() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedEdgeContext>().detail;

    view! {
        <div class="wf-detail-actions">
            <button
                class="wf-detail-btn wf-detail-btn-primary"
                type="button"
                on:click=move |_| {
                    if let Some(current) = detail.get() {
                        workflow.canvas.expand_block(current.edge.from_node_id);
                    }
                }
            >
                "Open source"
            </button>
            <button
                class="wf-detail-btn"
                type="button"
                on:click=move |_| {
                    if let Some(current) = detail.get() {
                        workflow.canvas.expand_block(current.edge.to_node_id);
                    }
                }
            >
                "Open next step"
            </button>
            <Show when=move || {
                detail
                    .get()
                    .and_then(|current| current.source_block)
                    .is_some_and(|block| can_insert_block_ref(&block))
            }>
                <button
                    class="wf-detail-btn"
                    type="button"
                    on:click=move |_| {
                        if let Some(current) = detail.get() {
                            workflow.canvas.insert_block_ref(current.edge.from_node_id);
                        }
                    }
                >
                    "Use source in next step"
                </button>
            </Show>
        </div>
    }
}

#[component]
fn WorkflowEdgeTechnicalDetail() -> impl IntoView {
    let workflow = expect_context::<WorkflowSurfaceContext>();
    let detail = expect_context::<WorkflowSelectedEdgeContext>().detail;

    view! {
        <details class="wf-detail-technical">
            <summary>"Technical detail"</summary>
            <div class="wf-detail-technical-list">
                <div class="wf-detail-technical-row">
                    <span class="wf-detail-technical-key">"Edge id"</span>
                    <code class="wf-detail-technical-value">
                        {move || detail.get().map(|current| current.edge.id).unwrap_or_default()}
                    </code>
                </div>
                <div class="wf-detail-technical-row">
                    <span class="wf-detail-technical-key">"State"</span>
                    <code class="wf-detail-technical-value">
                        {move || {
                            detail
                                .get()
                                .map(|current| format!("{:?}", current.edge.state).to_lowercase())
                                .unwrap_or_default()
                        }}
                    </code>
                </div>
                <div class="wf-detail-technical-row">
                    <span class="wf-detail-technical-key">"Graph size"</span>
                    <code class="wf-detail-technical-value">
                        {format!(
                            "{} nodes / {} edges",
                            workflow.graph.get().nodes.len(),
                            workflow.graph.get().edges.len()
                        )}
                    </code>
                </div>
            </div>
        </details>
    }
}

fn block_detail_context(
    workflow: &WorkflowSurfaceContext,
    block: CanvasBlock,
) -> WorkflowBlockDetailContext {
    let graph_node = workflow
        .graph
        .get()
        .nodes
        .into_iter()
        .find(|node| node.id == block.id);
    let title = block_title(&block);
    let intent = block_intent_line(&block, &title);
    WorkflowBlockDetailContext {
        title,
        source: block_source_label(&block, graph_node.as_ref()),
        artifact: render_artifact_label(&block),
        intent,
        summary: detail_summary(&block),
        disclosures: disclosure_items(&block),
        returns: return_items(&block),
        permission_window: permission_window_copy(&block),
        technical_state: technical_state_name(&block.state),
        linked: block.linked_block_ids.clone(),
        schema_type: block.schema_type.clone(),
        agent_did: block.agent_did.clone(),
        technical_action: block_action_type(&block),
        upstream: relation_blocks(&workflow.graph.get(), &workflow.blocks.get(), &block.id, true),
        downstream: relation_blocks(
            &workflow.graph.get(),
            &workflow.blocks.get(),
            &block.id,
            false,
        ),
        can_insert_ref: can_insert_block_ref(&block),
        can_retry: matches!(&block.state, BlockState::Failed { .. }),
        plan: if let BlockState::AwaitingApproval { plan } = &block.state {
            Some(plan.clone())
        } else {
            None
        },
        detail_state_label: workflow_state_label(&block.state).to_string(),
        needs_empty_copy: matches!(
            &block.state,
            BlockState::AwaitingApproval { .. } | BlockState::Ghost { .. }
        ),
        block,
    }
}

fn edge_detail_context(
    workflow: &WorkflowSurfaceContext,
    edge: WorkflowEdge,
) -> WorkflowEdgeDetailContext {
    WorkflowEdgeDetailContext {
        source_title: block_label_by_id(&workflow.blocks.get(), &edge.from_node_id),
        target_title: block_label_by_id(&workflow.blocks.get(), &edge.to_node_id),
        relationship: edge_relationship_copy(&edge),
        source_block: workflow
            .blocks
            .get()
            .into_iter()
            .find(|block| block.id == edge.from_node_id),
        edge,
    }
}

fn build_workflow_map(graph: &WorkflowGraph, blocks: &[CanvasBlock]) -> WorkflowMapView {
    let block_map = blocks
        .iter()
        .cloned()
        .map(|block| (block.id.clone(), block))
        .collect::<BTreeMap<_, _>>();

    let node_seeds = if graph.nodes.is_empty() {
        blocks
            .iter()
            .enumerate()
            .map(|(index, block)| WorkflowNode {
                id: block.id.clone(),
                node_type: if matches!(block.state, BlockState::Outcome { .. }) {
                    PipelineNodeType::Synthesizer
                } else {
                    PipelineNodeType::Agent
                },
                intent: block.prompt_text.clone().unwrap_or_default(),
                agent_name: None,
                agent_did: block.agent_did.clone(),
                pap_uri: None,
                action_type: String::new(),
                input_ports: Vec::new(),
                output_ports: Vec::new(),
                template_override: None,
                position_x: (index as f64) * COLUMN_GAP,
                position_y: 0.0,
            })
            .collect::<Vec<_>>()
    } else {
        graph.nodes.clone()
    };

    let edge_seeds = graph.edges.clone();
    let node_ids = node_seeds
        .iter()
        .filter(|node| block_map.contains_key(&node.id))
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();

    let mut columns = node_ids
        .iter()
        .map(|id| (id.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();

    for _ in 0..node_ids.len() {
        let mut changed = false;
        for edge in &edge_seeds {
            let from_column = *columns.get(&edge.from_node_id).unwrap_or(&0);
            let entry = columns.entry(edge.to_node_id.clone()).or_insert(0);
            if *entry < from_column + 1 {
                *entry = from_column + 1;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut rows_by_column = BTreeMap::<usize, usize>::new();
    let mut nodes = Vec::new();
    let mut positions = BTreeMap::<String, (f64, f64)>::new();

    for node in node_seeds {
        let Some(block) = block_map.get(&node.id).cloned() else {
            continue;
        };
        let column = *columns.get(&node.id).unwrap_or(&0);
        let row_entry = rows_by_column.entry(column).or_insert(0);
        let row = *row_entry;
        *row_entry += 1;

        let x = BOARD_PADDING_X + column as f64 * COLUMN_GAP;
        let y = BOARD_PADDING_Y + row as f64 * ROW_GAP;

        positions.insert(node.id.clone(), (x, y));
        nodes.push(WorkflowMapNode {
            incoming: edge_seeds
                .iter()
                .filter(|edge| edge.to_node_id == node.id)
                .count(),
            outgoing: edge_seeds
                .iter()
                .filter(|edge| edge.from_node_id == node.id)
                .count(),
            graph_node: node,
            block,
            x,
            y,
        });
    }

    let edges = edge_seeds
        .into_iter()
        .filter_map(|edge| {
            let (from_x, from_y) = positions.get(&edge.from_node_id)?;
            let (to_x, to_y) = positions.get(&edge.to_node_id)?;
            let start_x = from_x + NODE_WIDTH;
            let start_y = from_y + NODE_HEIGHT * 0.5;
            let end_x = *to_x;
            let end_y = to_y + NODE_HEIGHT * 0.5;
            let control = ((end_x - start_x).abs() * 0.48).max(56.0);
            let arc_lift = if (start_y - end_y).abs() < 1.0 { 44.0 } else { 0.0 };
            let control_y = start_y.min(end_y) - arc_lift;
            let min_x = start_x.min(end_x) - 12.0;
            let max_x = start_x.max(end_x) + 12.0;
            let min_y = start_y.min(end_y).min(control_y) - 12.0;
            let max_y = start_y.max(end_y).max(control_y) + 12.0;
            Some(WorkflowMapEdge {
                path: format!(
                    "M {start_x} {start_y} C {} {}, {} {}, {end_x} {end_y}",
                    start_x + control,
                    start_y - arc_lift,
                    end_x - control,
                    end_y - arc_lift
                ),
                hitbox_x: min_x,
                hitbox_y: min_y,
                hitbox_width: (max_x - min_x).max(24.0),
                hitbox_height: (max_y - min_y).max(24.0),
                edge,
            })
        })
        .collect::<Vec<_>>();

    let width = nodes
        .iter()
        .map(|node| node.x + NODE_WIDTH + BOARD_PADDING_X)
        .fold(0.0, f64::max);
    let height = nodes
        .iter()
        .map(|node| node.y + NODE_HEIGHT + BOARD_PADDING_Y)
        .fold(0.0, f64::max);

    WorkflowMapView {
        nodes,
        edges,
        width,
        height,
    }
}

fn workflow_summary(blocks: &[CanvasBlock], graph: &WorkflowGraph) -> String {
    if blocks.is_empty() {
        return "Papillon will sketch the workflow here after the first real step.".into();
    }

    let approvals = blocks
        .iter()
        .filter(|block| matches!(block.state, BlockState::AwaitingApproval { .. }))
        .count();
    let previews = blocks
        .iter()
        .filter(|block| matches!(block.state, BlockState::Ghost { .. }))
        .count();
    let resolved = blocks
        .iter()
        .filter(|block| matches!(block.state, BlockState::Resolved | BlockState::Outcome { .. }))
        .count();

    let mut parts = vec![format!("{} {}", blocks.len(), pluralize(blocks.len(), "step", "steps"))];
    if approvals > 0 {
        parts.push(format!("{approvals} waiting on you"));
    }
    if previews > 0 {
        parts.push(format!("{previews} still in preview"));
    }
    if resolved > 0 {
        parts.push(format!("{resolved} already rendered"));
    }
    if !graph.edges.is_empty() {
        parts.push(format!(
            "{} {} between them",
            graph.edges.len(),
            pluralize(graph.edges.len(), "relationship", "relationships")
        ));
    }
    parts.join(" · ")
}

fn workflow_state_label(state: &BlockState) -> &'static str {
    match state {
        BlockState::Ghost { .. } => "Preview",
        BlockState::AwaitingApproval { .. } => "Needs approval",
        BlockState::Resolving { .. } => "Working",
        BlockState::Resolved => "Result",
        BlockState::Failed { .. } => "Failed",
        BlockState::Outcome { .. } => "Outcome",
        BlockState::Note { .. } => "Note",
        BlockState::Guide { .. } => "Guide",
    }
}

fn workflow_state_class(state: &BlockState) -> &'static str {
    match state {
        BlockState::Ghost { .. } => "is-preview",
        BlockState::AwaitingApproval { .. } => "is-approval",
        BlockState::Resolving { .. } => "is-working",
        BlockState::Resolved => "is-result",
        BlockState::Failed { .. } => "is-failed",
        BlockState::Outcome { .. } => "is-outcome",
        BlockState::Note { .. } => "is-note",
        BlockState::Guide { .. } => "is-guide",
    }
}

fn workflow_edge_class(edge: &WorkflowEdge) -> &'static str {
    match edge.state {
        papillon_shared::EdgeState::Confirmed => "state-confirmed",
        papillon_shared::EdgeState::Proposed => "state-proposed",
        papillon_shared::EdgeState::Blocked => "state-blocked",
        papillon_shared::EdgeState::Unconnected => "state-unconnected",
    }
}

fn block_title(block: &CanvasBlock) -> String {
    match &block.state {
        BlockState::Note { title, .. } if !title.trim().is_empty() => title.trim().into(),
        BlockState::Resolved | BlockState::Outcome { .. } => render_artifact_label(block),
        BlockState::Ghost { returns_preview, .. } if !returns_preview.is_empty() => {
            render_label_for_schema(&returns_preview[0])
        }
        BlockState::AwaitingApproval { plan } if !plan.returns.is_empty() => {
            render_label_for_schema(&plan.returns[0])
        }
        _ => block
            .prompt_text
            .clone()
            .filter(|text| !text.trim().is_empty())
            .unwrap_or_else(|| fallback_block_title(block)),
    }
}

fn fallback_block_title(block: &CanvasBlock) -> String {
    match &block.state {
        BlockState::Ghost { agent_name, .. } => format!("Preview for {agent_name}"),
        BlockState::AwaitingApproval { plan } => format!("Approval for {}", plan.selected_agent_name),
        BlockState::Resolving { phase_label, .. } if !phase_label.trim().is_empty() => {
            phase_label.clone()
        }
        BlockState::Failed { .. } => "This step failed".into(),
        BlockState::Outcome { .. } => "Combined result".into(),
        BlockState::Note { .. } => "Note".into(),
        _ => render_artifact_label(block),
    }
}

fn block_intent_line(block: &CanvasBlock, title: &str) -> Option<String> {
    block.prompt_text
        .as_ref()
        .map(|text| text.trim())
        .filter(|text| !text.is_empty())
        .and_then(|text| {
            if text.eq_ignore_ascii_case(title) {
                None
            } else {
                Some(text.to_string())
            }
        })
}

fn block_source_label(block: &CanvasBlock, graph_node: Option<&WorkflowNode>) -> String {
    if let Some(agent_name) = graph_node.and_then(|node| node.agent_name.clone()) {
        return agent_name;
    }

    match &block.state {
        BlockState::Ghost { agent_name, .. } => agent_name.clone(),
        BlockState::AwaitingApproval { plan } => plan.selected_agent_name.clone(),
        BlockState::Outcome { .. } => "Papillon".into(),
        BlockState::Note { .. } => "Personal note".into(),
        BlockState::Resolved => "Agent result".into(),
        BlockState::Resolving { .. } => "Working step".into(),
        BlockState::Failed { .. } => "Stopped step".into(),
        BlockState::Guide { .. } => "Guide".into(),
    }
}

fn render_artifact_label(block: &CanvasBlock) -> String {
    match &block.state {
        BlockState::Note { .. } => "Saved note".into(),
        BlockState::Outcome { provenance_block_ids } => {
            format!(
                "Combined {}",
                pluralize(
                    provenance_block_ids.len().max(1),
                    "result",
                    "results",
                )
            )
        }
        BlockState::Ghost { returns_preview, .. } if !returns_preview.is_empty() => {
            render_label_for_schema(&returns_preview[0])
        }
        BlockState::AwaitingApproval { plan } if !plan.returns.is_empty() => {
            render_label_for_schema(&plan.returns[0])
        }
        _ => block
            .schema_type
            .as_deref()
            .map(render_label_for_schema)
            .unwrap_or_else(|| "Rendered block".into()),
    }
}

fn node_summary(block: &CanvasBlock, incoming: usize, outgoing: usize) -> String {
    let base = match &block.state {
        BlockState::Ghost {
            disclosure_preview,
            returns_preview,
            ..
        } => {
            if disclosure_preview.is_empty() {
                format!("No extra data needed · {}", preview_returns(returns_preview))
            } else {
                format!(
                    "Needs {} · {}",
                    count_phrase(disclosure_preview.len(), "shared item", "shared items"),
                    preview_returns(returns_preview)
                )
            }
        }
        BlockState::AwaitingApproval { plan } => {
            let share_copy = if plan.requires_disclosure.is_empty() {
                "No extra data needed".into()
            } else {
                format!(
                    "Needs {}",
                    count_phrase(plan.requires_disclosure.len(), "shared item", "shared items")
                )
            };
            format!("{share_copy} · {}", preview_returns(&plan.returns))
        }
        BlockState::Resolving { phase_label, .. } => {
            if phase_label.trim().is_empty() {
                "Negotiating".into()
            } else {
                phase_label.clone()
            }
        }
        BlockState::Resolved => render_artifact_label(block),
        BlockState::Failed { reason, .. } => humanize_reason(reason),
        BlockState::Outcome { provenance_block_ids } => format!(
            "Combines {}",
            count_phrase(provenance_block_ids.len(), "upstream block", "upstream blocks")
        ),
        BlockState::Note { .. } => "You can reuse this as context later".into(),
        BlockState::Guide { .. } => String::new(),
    };

    let relation = match (incoming, outgoing) {
        (0, 0) => None,
        (incoming, 0) => Some(format!(
            "uses {}",
            count_phrase(incoming, "step", "steps")
        )),
        (0, outgoing) => Some(format!(
            "feeds {}",
            count_phrase(outgoing, "step", "steps")
        )),
        (incoming, outgoing) => Some(format!(
            "uses {} · feeds {}",
            count_phrase(incoming, "step", "steps"),
            count_phrase(outgoing, "step", "steps")
        )),
    };

    relation.map(|relation| format!("{base} · {relation}")).unwrap_or(base)
}

fn detail_summary(block: &CanvasBlock) -> String {
    match &block.state {
        BlockState::Ghost { .. } => {
            "Papillon has matched a step but has not asked for permission yet.".into()
        }
        BlockState::AwaitingApproval { plan } => {
            if plan.requires_disclosure.is_empty() {
                "Papillon is ready to run this step as soon as you allow it.".into()
            } else {
                "Papillon found a step that can do this. Review what it wants to use before it runs."
                    .into()
            }
        }
        BlockState::Resolving { phase_label, .. } => {
            if phase_label.trim().is_empty() {
                "Papillon is working through the handshake.".into()
            } else {
                format!("Papillon is currently in {phase_label}.")
            }
        }
        BlockState::Resolved => "This step has already returned something you can use.".into(),
        BlockState::Failed { .. } => {
            "This step stopped before it could finish. You can inspect it or try again.".into()
        }
        BlockState::Outcome { provenance_block_ids } => format!(
            "Papillon merged {} into a single usable result.",
            count_phrase(
                provenance_block_ids.len().max(1),
                "upstream block",
                "upstream blocks"
            )
        ),
        BlockState::Note { .. } => "This block is your own material, not an agent result.".into(),
        BlockState::Guide { .. } => String::new(),
    }
}

fn disclosure_items(block: &CanvasBlock) -> Vec<String> {
    match &block.state {
        BlockState::Ghost {
            disclosure_preview,
            ..
        } => disclosure_preview.clone(),
        BlockState::AwaitingApproval { plan } => plan.requires_disclosure.clone(),
        _ => Vec::new(),
    }
}

fn return_items(block: &CanvasBlock) -> Vec<String> {
    match &block.state {
        BlockState::Ghost { returns_preview, .. } => returns_preview.clone(),
        BlockState::AwaitingApproval { plan } => plan.returns.clone(),
        BlockState::Resolved | BlockState::Outcome { .. } => {
            block.schema_type.clone().into_iter().collect::<Vec<_>>()
        }
        BlockState::Note { .. } => vec!["note".into()],
        _ => Vec::new(),
    }
}

fn permission_window_copy(block: &CanvasBlock) -> Option<String> {
    match &block.state {
        BlockState::AwaitingApproval { plan } => Some(format!(
            "If you allow it, this permission lasts about {}.",
            format_duration_hours(plan.ttl_hours)
        )),
        _ => None,
    }
}

fn relation_blocks(
    graph: &WorkflowGraph,
    blocks: &[CanvasBlock],
    block_id: &str,
    upstream: bool,
) -> Vec<(String, String)> {
    let block_lookup = blocks
        .iter()
        .map(|block| (block.id.clone(), block))
        .collect::<BTreeMap<_, _>>();

    let mut related = Vec::new();
    for edge in &graph.edges {
        let maybe_id = if upstream && edge.to_node_id == block_id {
            Some(edge.from_node_id.clone())
        } else if !upstream && edge.from_node_id == block_id {
            Some(edge.to_node_id.clone())
        } else {
            None
        };

        if let Some(id) = maybe_id {
            let label = block_lookup
                .get(&id)
                .map(|block| block_title(block))
                .unwrap_or_else(|| id.clone());
            related.push((id, label));
        }
    }

    related
}

fn block_label_by_id(blocks: &[CanvasBlock], block_id: &str) -> String {
    blocks
        .iter()
        .find(|block| block.id == block_id)
        .map(block_title)
        .unwrap_or_else(|| block_id.to_string())
}

fn block_action_type(block: &CanvasBlock) -> Option<String> {
    match &block.state {
        BlockState::Ghost { action_type, .. } if !action_type.is_empty() => Some(action_type.clone()),
        BlockState::AwaitingApproval { plan } if !plan.action.is_empty() => Some(plan.action.clone()),
        _ => None,
    }
}

fn technical_state_name(state: &BlockState) -> &'static str {
    match state {
        BlockState::Ghost { .. } => "ghost",
        BlockState::AwaitingApproval { .. } => "awaiting_approval",
        BlockState::Resolving { .. } => "resolving",
        BlockState::Resolved => "resolved",
        BlockState::Failed { .. } => "failed",
        BlockState::Outcome { .. } => "outcome",
        BlockState::Guide { .. } => "guide",
        BlockState::Note { .. } => "note",
    }
}

fn can_insert_block_ref(block: &CanvasBlock) -> bool {
    matches!(
        block.state,
        BlockState::Resolved | BlockState::Outcome { .. } | BlockState::Note { .. }
    )
}

fn preview_returns(returns: &[String]) -> String {
    if returns.is_empty() {
        "returns a result".into()
    } else {
        format!("returns {}", preview_list(returns))
    }
}

fn preview_list(items: &[String]) -> String {
    let rendered = items
        .iter()
        .take(2)
        .map(|item| describe_output_item(item))
        .collect::<Vec<_>>();
    if items.len() > 2 {
        format!("{} +{}", rendered.join(", "), items.len() - 2)
    } else {
        rendered.join(", ")
    }
}

fn edge_relationship_copy(edge: &WorkflowEdge) -> String {
    if edge.id.starts_with("map-linked-") {
        "Papillon kept these blocks tied together because they belong to the same result path."
            .into()
    } else {
        "The later step explicitly uses the earlier block as context.".into()
    }
}

fn describe_output_item(item: &str) -> String {
    if !item.contains('.') && item.contains(':') {
        user_visible_schema_type_label(item)
    } else {
        humanize_schema_term(item)
    }
}

fn format_duration_hours(hours: u32) -> String {
    if hours == 1 {
        "1 hour".into()
    } else {
        format!("{hours} hours")
    }
}

fn count_phrase(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", pluralize(count, singular, plural))
}

fn pluralize<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 {
        singular
    } else {
        plural
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
    let needs = plan.requires_disclosure.clone();
    let has_needs = !needs.is_empty();
    let returns = plan.returns.clone();
    let agent_name = plan.selected_agent_name.clone();
    let permission_copy = format!("About {}", format_duration_hours(plan.ttl_hours));

    view! {
        <div class="wf-approval-plan">
            <div class="wf-plan-agent-row">
                <span class="wf-plan-label">"Handled by"</span>
                <span class="wf-plan-value">{agent_name}</span>
            </div>

            <Show
                when=move || has_needs
                fallback=move || view! {
                    <div class="wf-plan-disclosure">
                        "No extra personal data needed"
                    </div>
                }
            >
                {needs.iter().map(|item| {
                    let label = humanize_schema_term(item);
                    view! {
                        <div class="wf-plan-disclosure">
                            <span class="wf-plan-check">"\u{1f512} "</span>
                            <span>{label}</span>
                        </div>
                    }
                }).collect::<Vec<_>>()}
            </Show>

            <div class="wf-plan-returns">
                <span class="wf-plan-label">"Likely result"</span>
                <span class="wf-plan-value">
                    {if returns.is_empty() {
                        "Result".to_string()
                    } else {
                        preview_list(&returns)
                    }}
                </span>
            </div>

            <div class="wf-plan-ttl">
                <span class="wf-plan-label">"Permission lasts"</span>
                <span class="wf-plan-value">{permission_copy}</span>
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
            candidates: vec![],
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
