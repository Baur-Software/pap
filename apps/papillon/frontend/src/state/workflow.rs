use leptos::prelude::*;
use papillon_shared::{
    BlockState, Canvas, EdgeState, PipelineNodeType, PortRef, WorkflowEdge, WorkflowGraph,
    WorkflowMode, WorkflowNode,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

// ─────────────────────────────────────────────────────────────────────────────
// Design-mode wiring types (local to workflow state, not in shared types)
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks an in-progress edge drag from an output port.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeDrag {
    pub from_node_id: String,
    pub from_port_idx: usize,
}

/// A saved workflow template — persisted to settings DB or localStorage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub nodes: Vec<WorkflowNode>,
    pub edges: Vec<WorkflowEdge>,
    pub gates: Vec<WorkflowGate>,
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
}

/// An approval gate inserted between two nodes on a given edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowGate {
    pub id: String,
    /// The edge this gate is attached to (edge.id).
    pub preceding_edge_id: String,
    pub mode: GateMode,
}

/// Gate approval strategy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GateMode {
    /// Pause execution until the principal explicitly approves.
    Manual,
    /// Auto-approve after the specified number of minutes.
    AutoApprove { after_minutes: u32 },
}

impl std::fmt::Display for GateMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateMode::Manual => write!(f, "Manual"),
            GateMode::AutoApprove { after_minutes } => {
                write!(f, "Auto ({after_minutes} min)")
            }
        }
    }
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
    /// Active edge drag state — set when an output port is clicked.
    pub dragging_edge: RwSignal<Option<EdgeDrag>>,
    /// Approval gates placed on edges in the design graph.
    pub gates: RwSignal<Vec<WorkflowGate>>,
    /// Saved workflow templates — persisted via Tauri IPC or localStorage fallback.
    pub saved_templates: RwSignal<Vec<WorkflowTemplate>>,
}

impl WorkflowState {
    pub fn new() -> Self {
        Self {
            graph: RwSignal::new(WorkflowGraph::default()),
            mode: RwSignal::new(WorkflowMode::default()),
            design_nodes: RwSignal::new(Vec::new()),
            design_edges: RwSignal::new(Vec::new()),
            dragging_edge: RwSignal::new(None),
            gates: RwSignal::new(Vec::new()),
            saved_templates: RwSignal::new(Vec::new()),
        }
    }

    /// Cancel any in-progress edge drag.
    pub fn cancel_wiring(&self) {
        self.dragging_edge.set(None);
    }

    // ── Template management ─────────────────────────────────────────────────

    /// Generate an ISO 8601 timestamp for the current instant.
    fn now_iso() -> String {
        js_sys::Date::new_0()
            .to_iso_string()
            .as_string()
            .unwrap_or_default()
    }

    /// Save the current design graph (nodes, edges, gates) as a named template.
    pub fn save_current_workflow(&self, name: String, description: String, graph: &WorkflowGraph) {
        let id = format!("tpl-{}", js_sys::Math::random().to_bits());
        let now = Self::now_iso();
        let template = WorkflowTemplate {
            id,
            name,
            description,
            nodes: graph.nodes.clone(),
            edges: graph.edges.clone(),
            gates: self.gates.get_untracked(),
            version: 1,
            created_at: now.clone(),
            updated_at: now,
        };
        self.saved_templates.update(|ts| ts.push(template));
        self.persist_templates();
    }

    /// Load a saved template into the design graph by template ID.
    /// Returns `true` if the template was found and loaded.
    pub fn load_template(&self, template_id: &str, graph: RwSignal<WorkflowGraph>) -> bool {
        let templates = self.saved_templates.get_untracked();
        if let Some(tpl) = templates.iter().find(|t| t.id == template_id) {
            graph.set(WorkflowGraph {
                nodes: tpl.nodes.clone(),
                edges: tpl.edges.clone(),
                is_designed: true,
            });
            self.gates.set(tpl.gates.clone());
            true
        } else {
            false
        }
    }

    /// Delete a saved template by ID.
    pub fn delete_template(&self, template_id: &str) {
        self.saved_templates
            .update(|ts| ts.retain(|t| t.id != template_id));
        self.persist_templates();
    }

    /// Export a template as a JSON string for sharing.
    pub fn export_template_json(&self, template_id: &str) -> Option<String> {
        let templates = self.saved_templates.get_untracked();
        templates
            .iter()
            .find(|t| t.id == template_id)
            .and_then(|t| serde_json::to_string_pretty(t).ok())
    }

    /// Import a template from a JSON string. Returns an error message on failure.
    pub fn import_template_json(&self, json: &str) -> Result<(), String> {
        let mut tpl: WorkflowTemplate =
            serde_json::from_str(json).map_err(|e| format!("Invalid JSON: {e}"))?;
        // Assign a new ID to avoid collisions with existing templates.
        tpl.id = format!("tpl-{}", js_sys::Math::random().to_bits());
        tpl.updated_at = Self::now_iso();
        self.saved_templates.update(|ts| ts.push(tpl));
        self.persist_templates();
        Ok(())
    }

    /// Persist templates to localStorage (fallback when Tauri is unavailable).
    /// When Tauri is available the save is issued via IPC in a spawn_local call.
    fn persist_templates(&self) {
        #[cfg(target_arch = "wasm32")]
        {
            let templates = self.saved_templates.get_untracked();
            let json = serde_json::to_string(&templates).unwrap_or_default();
            use crate::bridge;
            if bridge::tauri_available() {
                // Fire-and-forget Tauri IPC save
                let json_for_ipc = json.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let args = serde_json::json!({ "templates_json": json_for_ipc });
                    let _ = bridge::invoke::<serde_json::Value, ()>(
                        "save_workflow_templates",
                        &args,
                    )
                    .await;
                });
            } else if let Some(storage) = web_sys::window()
                .and_then(|w| w.local_storage().ok().flatten())
            {
                let _ = storage.set_item("papillon_workflow_templates", &json);
            }
        }
    }

    /// Load templates from Tauri IPC or localStorage on startup.
    /// Call once during initialization.
    pub fn hydrate_templates(&self) {
        #[cfg(target_arch = "wasm32")]
        {
            use crate::bridge;
            let saved_templates = self.saved_templates;
            if bridge::tauri_available() {
                wasm_bindgen_futures::spawn_local(async move {
                    if let Ok(json_str) = bridge::invoke_no_args::<String>(
                        "list_workflow_templates",
                    )
                    .await
                    {
                        if let Ok(templates) =
                            serde_json::from_str::<Vec<WorkflowTemplate>>(&json_str)
                        {
                            saved_templates.set(templates);
                        }
                    }
                });
            } else if let Some(storage) = web_sys::window()
                .and_then(|w| w.local_storage().ok().flatten())
            {
                if let Ok(Some(json_str)) =
                    storage.get_item("papillon_workflow_templates")
                {
                    if let Ok(templates) =
                        serde_json::from_str::<Vec<WorkflowTemplate>>(&json_str)
                    {
                        saved_templates.set(templates);
                    }
                }
            }
        }
    }

    /// Check whether adding an edge from `from_id` to `to_id` would create a
    /// cycle in the current design graph. Uses iterative DFS from `to_id`
    /// following existing edges — if we can reach `from_id`, it is a cycle.
    pub fn would_create_cycle(&self, from_id: &str, to_id: &str, graph: &WorkflowGraph) -> bool {
        // DFS: starting from to_id, follow outgoing edges. If we reach from_id, it's a cycle.
        let mut visited = HashSet::new();
        let mut stack = vec![to_id.to_string()];
        while let Some(current) = stack.pop() {
            if current == from_id {
                return true;
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            for edge in &graph.edges {
                if edge.from_node_id == current {
                    stack.push(edge.to_node_id.clone());
                }
            }
        }
        false
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

#[cfg(test)]
mod workflow_state_tests {
    use super::*;

    #[test]
    fn edge_drag_display_fields() {
        let drag = EdgeDrag {
            from_node_id: "node-1".into(),
            from_port_idx: 0,
        };
        assert_eq!(drag.from_node_id, "node-1");
        assert_eq!(drag.from_port_idx, 0);
    }

    #[test]
    fn gate_mode_manual_display() {
        assert_eq!(format!("{}", GateMode::Manual), "Manual");
    }

    #[test]
    fn gate_mode_auto_display() {
        let mode = GateMode::AutoApprove { after_minutes: 15 };
        assert_eq!(format!("{}", mode), "Auto (15 min)");
    }

    #[test]
    fn would_create_cycle_detects_simple_cycle() {
        let state = WorkflowState::new();
        let graph = WorkflowGraph {
            nodes: vec![],
            edges: vec![
                WorkflowEdge {
                    id: "e1".into(),
                    from_node_id: "A".into(),
                    from_port: PortRef { path: "out".into(), label: "result".into(), required: false },
                    to_node_id: "B".into(),
                    to_port: PortRef { path: "in".into(), label: "input".into(), required: false },
                    state: EdgeState::Confirmed,
                    memex_remembered: false,
                },
                WorkflowEdge {
                    id: "e2".into(),
                    from_node_id: "B".into(),
                    from_port: PortRef { path: "out".into(), label: "result".into(), required: false },
                    to_node_id: "C".into(),
                    to_port: PortRef { path: "in".into(), label: "input".into(), required: false },
                    state: EdgeState::Confirmed,
                    memex_remembered: false,
                },
            ],
            is_designed: true,
        };
        // Adding C -> A would create a cycle (A -> B -> C -> A)
        assert!(state.would_create_cycle("C", "A", &graph));
    }

    #[test]
    fn would_create_cycle_no_cycle_for_dag() {
        let state = WorkflowState::new();
        let graph = WorkflowGraph {
            nodes: vec![],
            edges: vec![
                WorkflowEdge {
                    id: "e1".into(),
                    from_node_id: "A".into(),
                    from_port: PortRef { path: "out".into(), label: "result".into(), required: false },
                    to_node_id: "B".into(),
                    to_port: PortRef { path: "in".into(), label: "input".into(), required: false },
                    state: EdgeState::Confirmed,
                    memex_remembered: false,
                },
            ],
            is_designed: true,
        };
        // Adding B -> C does not create a cycle
        assert!(!state.would_create_cycle("B", "C", &graph));
    }

    #[test]
    fn would_create_cycle_self_loop() {
        let state = WorkflowState::new();
        let graph = WorkflowGraph {
            nodes: vec![],
            edges: vec![],
            is_designed: true,
        };
        // Adding A -> A is a self-loop — starting DFS from A, we immediately reach A
        assert!(state.would_create_cycle("A", "A", &graph));
    }

    #[test]
    fn workflow_gate_equality() {
        let gate1 = WorkflowGate {
            id: "g1".into(),
            preceding_edge_id: "e1".into(),
            mode: GateMode::Manual,
        };
        let gate2 = WorkflowGate {
            id: "g1".into(),
            preceding_edge_id: "e1".into(),
            mode: GateMode::Manual,
        };
        assert_eq!(gate1, gate2);
    }

    #[test]
    fn workflow_gate_auto_approve_modes() {
        let gate5 = WorkflowGate {
            id: "g1".into(),
            preceding_edge_id: "e1".into(),
            mode: GateMode::AutoApprove { after_minutes: 5 },
        };
        let gate30 = WorkflowGate {
            id: "g2".into(),
            preceding_edge_id: "e1".into(),
            mode: GateMode::AutoApprove { after_minutes: 30 },
        };
        assert_ne!(gate5, gate30);
    }
}
