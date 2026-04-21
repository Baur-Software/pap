use leptos::prelude::*;
use papillon_shared::{
    BlockState, Canvas, EdgeState, PipelineNodeType, PortRef, WorkflowEdge, WorkflowGraph,
    WorkflowMode, WorkflowNode,
};

/// Extract block IDs from `{{block:ID}}` patterns in prompt text.
/// Mirrors the private helper in canvas.rs — duplicated here to keep
/// this module self-contained with no cross-module private dependencies.
fn extract_block_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut remaining = text;
    while let Some(start) = remaining.find("{{block:") {
        let after = &remaining[start + 8..];
        if let Some(end) = after.find("}}") {
            let id = &after[..end];
            if !id.is_empty() {
                ids.push(id.to_string());
            }
            remaining = &after[end + 2..];
        } else {
            break;
        }
    }
    ids
}

/// Reactive workflow state context — mirrors the `CanvasState` Copy+Clone pattern.
/// All mutable state lives in Leptos `RwSignal` fields; the struct itself is a
/// thin, cheaply-copyable handle that can be passed freely through closures.
#[derive(Clone, Copy)]
pub struct WorkflowState {
    /// Map mode: auto-derived graph built from block events on the current canvas.
    pub graph: RwSignal<WorkflowGraph>,
    /// MAP or DESIGN sub-mode toggle.
    pub mode: RwSignal<WorkflowMode>,
    /// Design mode: principal-authored nodes (separate from Map-derived graph).
    pub design_nodes: RwSignal<Vec<WorkflowNode>>,
    /// Design mode: principal-authored edges.
    pub design_edges: RwSignal<Vec<WorkflowEdge>>,
}

impl WorkflowState {
    pub fn new() -> Self {
        Self {
            graph: RwSignal::new(WorkflowGraph::default()),
            mode: RwSignal::new(WorkflowMode::default()),
            design_nodes: RwSignal::new(Vec::new()),
            design_edges: RwSignal::new(Vec::new()),
        }
    }

    /// Derive the Map mode graph from the current canvas's blocks.
    ///
    /// Called after every `BlockResolved` event. Builds one `WorkflowNode` per
    /// non-guide / non-note block, and one `WorkflowEdge` per `{{block:ID}}`
    /// reference found in a block's prompt text.
    pub fn derive_map_graph(&self, canvas: &Canvas) {
        let mut nodes: Vec<WorkflowNode> = Vec::new();
        let mut edges: Vec<WorkflowEdge> = Vec::new();

        for block in &canvas.blocks {
            // Skip guide and note meta-blocks — they are not workflow steps.
            match &block.state {
                BlockState::Note { .. } | BlockState::Guide { .. } => continue,
                _ => {}
            }

            let x = nodes.len() as f64 * 240.0;
            let node = WorkflowNode {
                id: block.id.clone(),
                node_type: PipelineNodeType::Agent,
                intent: block.prompt_text.clone().unwrap_or_default(),
                agent_name: None, // humanized label populated in a future enhancement
                agent_did: block.agent_did.clone(),
                pap_uri: block.agent_did.as_ref().map(|d| format!("pap://{d}")),
                action_type: String::new(), // derived from block schema_type in a future enhancement
                input_ports: Vec::new(),
                output_ports: Vec::new(),
                template_override: None,
                position_x: x,
                position_y: 0.0,
            };
            nodes.push(node);

            // Build directed edges from `{{block:ID}}` references in the prompt.
            let prompt = block.prompt_text.as_deref().unwrap_or("");
            for referenced_id in extract_block_ids(prompt) {
                edges.push(WorkflowEdge {
                    id: format!("{referenced_id}->{}", block.id),
                    from_node_id: referenced_id,
                    from_port: PortRef {
                        path: String::new(),
                        label: "output".into(),
                        required: false,
                    },
                    to_node_id: block.id.clone(),
                    to_port: PortRef {
                        path: String::new(),
                        label: "input".into(),
                        required: false,
                    },
                    state: EdgeState::Confirmed,
                    memex_remembered: false,
                });
            }
        }

        self.graph.set(WorkflowGraph {
            nodes,
            edges,
            is_designed: false,
        });
    }
}

impl Default for WorkflowState {
    fn default() -> Self {
        Self::new()
    }
}
