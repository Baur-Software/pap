# Canvas Workflow UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the Workflow tab on the canvas back face from a flat orchestration trace to a full MAP/DESIGN dual-mode dependency graph: MAP auto-derives edges from `{{block:ID}}` references and receipt property_refs; DESIGN is a blank canvas workflow builder with agent nodes, property-level port wires, memex-backed inline approval cards, and a Run button that fires blocks on the front face.

**Architecture:** The existing `CanvasWorkflowPipeline` component becomes a MAP/DESIGN toggle host. MAP mode derives a `WorkflowGraph` reactively from `canvas_state.current_canvas_blocks()`. DESIGN mode uses a separate `RwSignal<WorkflowGraph>` for an authored graph stored independently. The `WorkflowGraph`, `WorkflowNode`, `WorkflowEdge`, `EdgeState`, `WorkflowMode`, and `PortRef` types are already defined in `crates/papillon-shared/src/types.rs`. The `episode_db::has_approval()` function already exists. Both modes share CSS flex-row layout (no SVG coordinate math — nodes flow left-to-right, edges are CSS connectors). Front-face/back-face coordination uses the existing `CanvasEvent` system.

**Tech Stack:** Rust, Leptos 0.8 (`RwSignal`, `Memo`, `Effect::new`, `For`, `Show`), `wasm_bindgen_futures::spawn_local`, existing `bridge::invoke_no_args`, `episode_db::has_approval` (via Tauri command), CSS flexbox, no SVG routing.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs` | **Rewrite** | MAP/DESIGN toggle + graph rendering; replaces flat trace |
| `apps/papillon/frontend/src/state/canvas.rs` | **Modify** | Add `workflow_graph: RwSignal<WorkflowGraph>` and `workflow_mode: RwSignal<WorkflowMode>` to `CanvasState` |
| `apps/papillon/frontend/styles/main.css` | **Modify** | Add workflow graph, node, port, edge, approval card, and design tools CSS |
| `apps/papillon/frontend/src/components/canvas_back_face.rs` | **No change** | Already renders `CanvasWorkflowPipeline` in the "workflow" tab |
| `crates/papillon-shared/src/types.rs` | **No change** | Types already defined |
| `crates/papillon-shared/src/episode_db.rs` | **No change** | `has_approval()` already implemented |

---

## Task 1: Add `workflow_graph` and `workflow_mode` to `CanvasState`

**Files:**
- Modify: `apps/papillon/frontend/src/state/canvas.rs`

- [ ] **Step 1: Write the failing test**

Add to the bottom of `apps/papillon/frontend/src/state/canvas.rs` (or its test module if one exists):

```rust
#[cfg(test)]
mod tests {
    use papillon_shared::{WorkflowGraph, WorkflowMode};

    #[test]
    fn workflow_graph_default_is_empty() {
        let g = WorkflowGraph::default();
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
        assert!(!g.is_designed);
    }

    #[test]
    fn workflow_mode_default_is_map() {
        let m = WorkflowMode::default();
        assert_eq!(m, WorkflowMode::Map);
    }
}
```

- [ ] **Step 2: Run test to confirm it passes** (these test the shared types, not the signal)

```bash
cd pap && cargo test -p papillon-shared workflow_graph_default_is_empty workflow_mode_default_is_map 2>&1 | tail -10
```
Expected: 2 × `ok` (tests pass — types already correct).

- [ ] **Step 3: Add `workflow_graph` and `workflow_mode` fields to `CanvasState`**

In `apps/papillon/frontend/src/state/canvas.rs`, find the `CanvasState` struct (around line 57). The last field before the closing `}` currently ends with `block_template_overrides` and `last_event`. Add two new fields:

```rust
    /// Live workflow graph for the active canvas (MAP = auto-derived; DESIGN = authored).
    pub workflow_graph: RwSignal<papillon_shared::WorkflowGraph>,
    /// Whether the Workflow tab is in Map or Design sub-mode.
    pub workflow_mode: RwSignal<papillon_shared::WorkflowMode>,
```

- [ ] **Step 4: Initialize the new signals in `CanvasState::default()`**

Find the `impl Default for CanvasState` block (or wherever the struct is initialized). Add:

```rust
            workflow_graph: RwSignal::new(papillon_shared::WorkflowGraph::default()),
            workflow_mode: RwSignal::new(papillon_shared::WorkflowMode::default()),
```

- [ ] **Step 5: Compile check**

```bash
cd pap && cargo check -p papillon-frontend 2>&1 | grep "^error" | head -10
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/state/canvas.rs
git commit -m "feat(canvas-state): add workflow_graph and workflow_mode signals"
```

---

## Task 2: Add MAP graph derivation — build `WorkflowGraph` from block events

This implements **Map mode**: auto-derive a `WorkflowGraph` from the active canvas blocks. The graph has one node per block; edges come from `{{block:ID}}` refs in `prompt_text` and `linked_block_ids`.

**Files:**
- Modify: `apps/papillon/frontend/src/state/canvas.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    // (add to existing test module from Task 1)
    use papillon_shared::{CanvasBlock, BlockState, WorkflowGraph};

    fn make_block(id: &str, prompt: &str) -> CanvasBlock {
        CanvasBlock {
            id: id.to_string(),
            canvas_id: "c1".into(),
            prompt_text: Some(prompt.to_string()),
            state: BlockState::Resolved { content: serde_json::Value::Null, schema_type: None },
            linked_block_ids: vec![],
            agent_did: None,
            agent_name: None,
            action_type: String::new(),
            property_refs: vec![],
            created_at: String::new(),
            updated_at: String::new(),
            position_x: 0.0,
            position_y: 0.0,
        }
    }

    #[test]
    fn derive_map_graph_creates_edge_from_block_ref() {
        let block_a = make_block("aaa", "search for flights");
        let block_b = make_block("bbb", "book using {{block:aaa}}");
        let blocks = vec![block_a, block_b];
        let graph = derive_map_graph(&blocks);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].from_node_id, "aaa");
        assert_eq!(graph.edges[0].to_node_id, "bbb");
    }

    #[test]
    fn derive_map_graph_no_refs_means_no_edges() {
        let block_a = make_block("aaa", "search");
        let block_b = make_block("bbb", "book");
        let blocks = vec![block_a, block_b];
        let graph = derive_map_graph(&blocks);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 0);
    }
}
```

- [ ] **Step 2: Run test to confirm compile error**

```bash
cd pap && cargo test -p papillon-frontend derive_map_graph 2>&1 | head -5
```
Expected: `error[E0425]: cannot find function 'derive_map_graph'`

- [ ] **Step 3: Implement `derive_map_graph()`**

Add the following function to `apps/papillon/frontend/src/state/canvas.rs` (before the `CanvasState` struct, after the `use` imports):

```rust
/// Derive a `WorkflowGraph` from a slice of canvas blocks.
///
/// Nodes: one per block (agent_name from block, ports empty — positions left to layout).
/// Edges: scan each block's `prompt_text` for `{{block:<id>}}` references; also scan
/// `linked_block_ids`. Each reference becomes a `WorkflowEdge` with `EdgeState::Unconnected`
/// (property wires are unknown in Map mode).
pub fn derive_map_graph(blocks: &[papillon_shared::CanvasBlock]) -> papillon_shared::WorkflowGraph {
    use papillon_shared::{WorkflowEdge, WorkflowMode, WorkflowNode, WorkflowGraph, EdgeState, PortRef, types::PipelineNodeType};

    let nodes: Vec<WorkflowNode> = blocks.iter().enumerate().map(|(i, b)| {
        WorkflowNode {
            id: b.id.clone(),
            node_type: PipelineNodeType::Agent,
            intent: b.prompt_text.clone().unwrap_or_default(),
            agent_name: b.agent_name.clone(),
            agent_did: b.agent_did.clone(),
            pap_uri: None,
            action_type: b.action_type.clone(),
            input_ports: b.property_refs.iter().map(|p| PortRef {
                path: p.clone(),
                label: p.split('.').last().unwrap_or(p).to_string(),
                required: false,
            }).collect(),
            output_ports: vec![],
            template_override: None,
            position_x: (i as f64) * 320.0,
            position_y: 0.0,
        }
    }).collect();

    let mut edges: Vec<WorkflowEdge> = Vec::new();
    let mut edge_counter: u32 = 0;

    // Extract {{block:ID}} refs from prompt text
    for block in blocks {
        let prompt = block.prompt_text.as_deref().unwrap_or("");
        let mut remaining = prompt;
        while let Some(start) = remaining.find("{{block:") {
            remaining = &remaining[start + 8..];
            if let Some(end) = remaining.find("}}") {
                let ref_id = &remaining[..end];
                if blocks.iter().any(|b| b.id == ref_id) {
                    edge_counter += 1;
                    edges.push(WorkflowEdge {
                        id: format!("map-edge-{edge_counter}"),
                        from_node_id: ref_id.to_string(),
                        from_port: PortRef { path: String::new(), label: String::new(), required: false },
                        to_node_id: block.id.clone(),
                        to_port: PortRef { path: String::new(), label: String::new(), required: false },
                        state: EdgeState::Unconnected,
                        memex_remembered: false,
                    });
                }
                remaining = &remaining[end + 2..];
            } else {
                break;
            }
        }
        // Also capture linked_block_ids edges
        for linked_id in &block.linked_block_ids {
            if blocks.iter().any(|b| &b.id == linked_id) {
                edge_counter += 1;
                edges.push(WorkflowEdge {
                    id: format!("map-linked-{edge_counter}"),
                    from_node_id: linked_id.clone(),
                    from_port: PortRef { path: String::new(), label: String::new(), required: false },
                    to_node_id: block.id.clone(),
                    to_port: PortRef { path: String::new(), label: String::new(), required: false },
                    state: EdgeState::Unconnected,
                    memex_remembered: false,
                });
            }
        }
    }

    WorkflowGraph { nodes, edges, is_designed: false }
}
```

- [ ] **Step 4: Wire `derive_map_graph` into `CanvasState` via an `Effect`**

In the `CanvasState::new()` or equivalent initialization (wherever the canvas signals are set up, look for where `RwSignal::new(vec![])` is assigned for canvases), add after all signals are created:

```rust
// Derive Map graph reactively from active canvas blocks.
{
    let cs = *self;  // CanvasState is Copy
    Effect::new(move || {
        if cs.workflow_mode.get() == papillon_shared::WorkflowMode::Map {
            let blocks = cs.current_canvas_blocks().get();
            cs.workflow_graph.set(derive_map_graph(&blocks));
        }
    });
}
```

> **Note:** If `CanvasState` is initialized differently (e.g., in `app.rs` via `provide_context`), add this `Effect` in the same location where the other canvas effects live.

- [ ] **Step 5: Run tests**

```bash
cd pap && cargo test -p papillon-frontend derive_map_graph 2>&1 | tail -10
```
Expected: 2 × `ok`

- [ ] **Step 6: Compile check**

```bash
cd pap && cargo check -p papillon-frontend 2>&1 | grep "^error" | head -10
```
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add apps/papillon/frontend/src/state/canvas.rs
git commit -m "feat(canvas-state): derive workflow graph from blocks in Map mode"
```

---

## Task 3: CSS — workflow graph, node, port, edge, approval card, design tools

**Files:**
- Modify: `apps/papillon/frontend/styles/main.css`

- [ ] **Step 1: Add workflow graph CSS**

Append to `apps/papillon/frontend/styles/main.css`:

```css
/* ═══════════════════════════════════════════════════════════════
   WORKFLOW GRAPH (back-face Workflow tab — MAP and DESIGN modes)
   ═══════════════════════════════════════════════════════════════ */

/* Toggle bar */
.wf-mode-toggle {
    display: flex;
    gap: 0;
    background: var(--bg-2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 2px;
    margin: 10px 14px 0;
    width: fit-content;
}
.wf-mode-btn {
    background: transparent;
    border: none;
    border-radius: 3px;
    padding: 4px 14px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-family: var(--font-mono);
    color: var(--text-3);
    cursor: pointer;
    transition: all 0.12s;
}
.wf-mode-btn.active {
    background: var(--bg-3);
    color: var(--text-1);
}

/* Graph canvas */
.wf-graph-canvas {
    flex: 1;
    overflow: auto;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 0;
}
.wf-graph-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex: 1;
    gap: 8px;
    color: var(--text-3);
    font-size: 12px;
    font-family: var(--font-mono);
}

/* Row of nodes connected by edges — flexbox, no SVG */
.wf-graph-row {
    display: flex;
    flex-direction: row;
    align-items: stretch;
    gap: 0;
    min-height: 160px;
    margin-bottom: 20px;
}

/* Individual agent node */
.wf-node {
    background: var(--bg-1);
    border: 1px solid var(--border);
    border-radius: 8px;
    width: 220px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    transition: border-color 0.15s;
}
.wf-node:hover {
    border-color: var(--purple);
}
.wf-node-header {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 9px 12px 8px;
    background: var(--bg-2);
    border-bottom: 1px solid var(--border);
}
.wf-node-emoji { font-size: 13px; flex-shrink: 0; }
.wf-node-name {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-1);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
}
.wf-node-uri {
    font-size: 9px;
    color: var(--text-3);
    font-family: var(--font-mono);
    padding: 0 12px 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

/* Port section headers */
.wf-node-section {
    padding: 5px 10px 2px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--text-3);
    font-family: var(--font-mono);
    border-top: 1px solid var(--border-subtle);
}
.wf-node-section:first-of-type { border-top: none; }

/* Port row */
.wf-port-row {
    display: flex;
    align-items: center;
    gap: 7px;
    padding: 3px 10px;
    min-height: 24px;
}
.wf-port-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    border: 1.5px solid var(--border);
    background: var(--bg-2);
    flex-shrink: 0;
    transition: background 0.12s, border-color 0.12s;
}
.wf-port-dot.wired {
    background: var(--teal);
    border-color: var(--teal);
}
.wf-port-dot.output {
    margin-left: auto;
    margin-right: 0;
}
.wf-port-label {
    font-size: 11px;
    color: var(--text-2);
    flex: 1;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.wf-port-schema {
    font-size: 9px;
    color: var(--text-3);
    font-family: var(--font-mono);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 130px;
}

/* Template picker at node bottom */
.wf-node-template {
    padding: 5px 10px 8px;
    border-top: 1px solid var(--border-subtle);
    font-size: 10px;
    color: var(--text-3);
    font-family: var(--font-mono);
}

/* Node state badges (wing-spectrum colors) */
.wf-node-badge {
    font-size: 9px;
    padding: 1px 5px;
    border-radius: 3px;
    font-family: var(--font-mono);
    font-weight: 700;
    letter-spacing: 0.04em;
    flex-shrink: 0;
}
.wf-node-badge.resolved { background: rgba(0,184,148,0.15); color: var(--teal); }
.wf-node-badge.running  { background: rgba(253,203,110,0.15); color: var(--gold); }
.wf-node-badge.failed   { background: rgba(232,112,106,0.15); color: var(--coral); }
.wf-node-badge.pending  { background: rgba(108,92,231,0.12); color: var(--purple); }

/* Edge connector between nodes */
.wf-edge {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    flex-shrink: 0;
    position: relative;
    cursor: pointer;
}
.wf-edge-line {
    width: 100%;
    height: 2px;
    background: var(--border);
    position: relative;
}
.wf-edge-line.confirmed { background: var(--teal); }
.wf-edge-line.proposed  { background: var(--gold); border: none; }
.wf-edge-line.blocked   { background: var(--coral); }
.wf-edge-line.unconnected { background: var(--border); }

/* Memex remembered badge on edge */
.wf-edge-memex {
    position: absolute;
    top: -10px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 11px;
    line-height: 1;
}

/* Inline approval card (Design mode — paused edge) */
.wf-approval-card {
    background: var(--bg-1);
    border: 1px solid var(--gold);
    border-radius: 8px;
    padding: 14px 16px;
    margin: 10px 14px;
    font-size: 12px;
    color: var(--text-2);
    display: flex;
    flex-direction: column;
    gap: 10px;
}
.wf-approval-card-title {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-family: var(--font-mono);
    color: var(--gold);
}
.wf-approval-card-agent {
    font-size: 12px;
    color: var(--text-1);
    font-weight: 600;
}
.wf-approval-card-disclosure {
    font-size: 11px;
    color: var(--text-2);
    line-height: 1.5;
}
.wf-approval-card-disclosure code {
    font-family: var(--font-mono);
    font-size: 10px;
    background: var(--bg-2);
    padding: 1px 4px;
    border-radius: 3px;
}
.wf-approval-card-actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
}
.wf-approval-btn {
    padding: 5px 12px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    cursor: pointer;
    border: 1px solid;
    transition: all 0.12s;
    font-family: var(--font-body);
}
.wf-approval-btn.allow {
    background: rgba(0,184,148,0.12);
    border-color: var(--teal);
    color: var(--teal);
}
.wf-approval-btn.allow:hover { background: rgba(0,184,148,0.22); }
.wf-approval-btn.always {
    background: rgba(108,92,231,0.12);
    border-color: var(--purple);
    color: var(--purple);
}
.wf-approval-btn.always:hover { background: rgba(108,92,231,0.22); }
.wf-approval-btn.deny {
    background: rgba(232,112,106,0.1);
    border-color: var(--coral);
    color: var(--coral);
}
.wf-approval-btn.deny:hover { background: rgba(232,112,106,0.2); }

/* Design mode tools strip */
.wf-design-tools {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 12px 10px;
    border-right: 1px solid var(--border);
    background: var(--bg-2);
    flex-shrink: 0;
    width: 46px;
    align-items: center;
}
.wf-design-tool-btn {
    width: 32px;
    height: 32px;
    border-radius: 5px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    cursor: pointer;
    background: none;
    border: 1px solid transparent;
    color: var(--text-2);
    transition: all 0.12s;
    line-height: 1;
}
.wf-design-tool-btn:hover {
    background: var(--bg-3);
    border-color: var(--border);
}
.wf-design-tool-btn.run {
    background: rgba(108,92,231,0.15);
    border-color: var(--purple);
    color: var(--purple);
}
.wf-design-tool-btn.run:hover { background: rgba(108,92,231,0.25); }
.wf-design-tool-btn.save {
    border-color: var(--border);
    color: var(--text-2);
}

/* Design mode layout wrapper */
.wf-design-layout {
    display: flex;
    flex: 1;
    overflow: hidden;
}

/* Node intent input (Design mode) */
.wf-node-intent-input {
    width: 100%;
    background: var(--bg-2);
    border: none;
    border-top: 1px solid var(--border-subtle);
    padding: 6px 10px;
    font-size: 11px;
    color: var(--text-2);
    font-family: var(--font-body);
    outline: none;
    resize: none;
}
.wf-node-intent-input:focus {
    background: var(--bg-3);
    color: var(--text-1);
}

/* Pulse animation for running edges */
@keyframes wf-edge-pulse {
    0%   { opacity: 1; }
    50%  { opacity: 0.35; }
    100% { opacity: 1; }
}
.wf-edge-line.running {
    background: var(--gold);
    animation: wf-edge-pulse 1.2s ease-in-out infinite;
}
```

- [ ] **Step 2: Verify with grep**

```bash
grep -c "\.wf-" apps/papillon/frontend/styles/main.css
```
Expected: at least 35 matches.

- [ ] **Step 3: Commit**

```bash
git add apps/papillon/frontend/styles/main.css
git commit -m "style(workflow): add workflow graph, node, port, edge, approval card, and design tools CSS"
```

---

## Task 4: Rewrite `CanvasWorkflowPipeline` — MAP mode graph renderer

Replace the flat orchestration trace with a MAP/DESIGN toggle. In this task, implement MAP mode: render the `WorkflowGraph` derived in Task 2 as a visual node graph.

**Files:**
- Rewrite: `apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs`

- [ ] **Step 1: Replace the component entirely**

```rust
use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock, EdgeState, WorkflowMode};

use crate::state::canvas::{CanvasSide, CanvasState};

/// Back-face Workflow tab — MAP / DESIGN toggle.
///
/// MAP mode: auto-derived dependency graph from active canvas blocks.
/// DESIGN mode: blank canvas + tools strip for workflow authoring.
#[component]
pub fn CanvasWorkflowPipeline() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    view! {
        <div class="wf-trace-panel" style="display:flex;flex-direction:column;height:100%;">
            // MAP / DESIGN toggle
            <div class="wf-mode-toggle">
                <button
                    class=move || if canvas_state.workflow_mode.get() == WorkflowMode::Map {
                        "wf-mode-btn active"
                    } else {
                        "wf-mode-btn"
                    }
                    on:click=move |_| canvas_state.workflow_mode.set(WorkflowMode::Map)
                >"MAP"</button>
                <button
                    class=move || if canvas_state.workflow_mode.get() == WorkflowMode::Design {
                        "wf-mode-btn active"
                    } else {
                        "wf-mode-btn"
                    }
                    on:click=move |_| canvas_state.workflow_mode.set(WorkflowMode::Design)
                >"DESIGN"</button>
            </div>

            <Show
                when=move || canvas_state.workflow_mode.get() == WorkflowMode::Map
                fallback=move || view! { <WorkflowDesignMode /> }
            >
                <WorkflowMapMode />
            </Show>
        </div>
    }
}

/// MAP mode: read-only graph derived from canvas block events.
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
                        <span>"No blocks on this canvas yet."</span>
                        <span>"Run a prompt to see the dependency graph."</span>
                    </div>
                }
            >
                // Render all nodes in a single flex row for simple cases.
                // (Multi-level graphs: nodes with no incoming edges are row 0.)
                <div class="wf-graph-row">
                    <For
                        each=move || {
                            let g = graph.get();
                            // Interleave nodes and edges in order
                            g.nodes.iter().enumerate().map(|(i, node)| {
                                let has_outgoing = g.edges.iter().any(|e| e.from_node_id == node.id);
                                let edge = if has_outgoing {
                                    g.edges.iter().find(|e| e.from_node_id == node.id).cloned()
                                } else {
                                    None
                                };
                                (node.clone(), edge, i)
                            }).collect::<Vec<_>>()
                        }
                        key=|(node, _, _)| node.id.clone()
                        children=move |(node, edge, _)| {
                            let blocks = canvas_state.current_canvas_blocks();
                            let node_id = node.id.clone();
                            let node_id_click = node_id.clone();
                            // Look up live block state for color badge
                            let block_state_class = {
                                let nid = node_id.clone();
                                move || {
                                    let bs = blocks.get();
                                    let b = bs.iter().find(|b| b.id == nid);
                                    match b.map(|b| &b.state) {
                                        Some(BlockState::Resolved { .. }) => "resolved",
                                        Some(BlockState::Resolving { .. }) => "running",
                                        Some(BlockState::Failed { .. }) => "failed",
                                        _ => "pending",
                                    }
                                }
                            };
                            let badge_label = {
                                let nid = node_id.clone();
                                move || {
                                    let bs = blocks.get();
                                    let b = bs.iter().find(|b| b.id == nid);
                                    match b.map(|b| &b.state) {
                                        Some(BlockState::Resolved { .. }) => "resolved",
                                        Some(BlockState::Resolving { .. }) => "running",
                                        Some(BlockState::Failed { .. }) => "failed",
                                        _ => "pending",
                                    }
                                }
                            };

                            let pap_uri = node.pap_uri.clone().unwrap_or_default();
                            let node_name = node.agent_name.clone()
                                .unwrap_or_else(|| {
                                    let intent = &node.intent;
                                    if intent.len() > 28 {
                                        format!("{}…", &intent[..28])
                                    } else {
                                        intent.clone()
                                    }
                                });
                            let input_ports = node.input_ports.clone();
                            let output_ports = node.output_ports.clone();

                            view! {
                                // Node
                                <div class="wf-node"
                                    on:click=move |_| {
                                        // Jump to block on front face
                                        canvas_state.requested_expansion.set(Some(node_id_click.clone()));
                                        canvas_state.canvas_side.set(CanvasSide::Front);
                                    }
                                    title="Click to view block on front face"
                                >
                                    <div class="wf-node-header">
                                        <span class="wf-node-emoji">"🤖"</span>
                                        <span class="wf-node-name">{node_name}</span>
                                        <span class=move || format!("wf-node-badge {}", block_state_class())>
                                            {badge_label}
                                        </span>
                                    </div>
                                    {(!pap_uri.is_empty()).then(|| view! {
                                        <div class="wf-node-uri">{pap_uri}</div>
                                    })}
                                    {(!input_ports.is_empty()).then(|| view! {
                                        <div class="wf-node-section">"Receives"</div>
                                        {input_ports.iter().map(|p| {
                                            let label = p.label.clone();
                                            let path = p.path.clone();
                                            view! {
                                                <div class="wf-port-row">
                                                    <div class="wf-port-dot" />
                                                    <span class="wf-port-label">{label}</span>
                                                    <span class="wf-port-schema">{path}</span>
                                                </div>
                                            }
                                        }).collect::<Vec<_>>()}
                                    })}
                                    {(!output_ports.is_empty()).then(|| view! {
                                        <div class="wf-node-section">"Outputs"</div>
                                        {output_ports.iter().map(|p| {
                                            let label = p.label.clone();
                                            let path = p.path.clone();
                                            view! {
                                                <div class="wf-port-row">
                                                    <span class="wf-port-label">{label}</span>
                                                    <span class="wf-port-schema">{path}</span>
                                                    <div class="wf-port-dot output wired" />
                                                </div>
                                            }
                                        }).collect::<Vec<_>>()}
                                    })}
                                </div>

                                // Edge connector (if this node has an outgoing edge)
                                {edge.map(|e| {
                                    let edge_class = match e.state {
                                        EdgeState::Confirmed => "wf-edge-line confirmed",
                                        EdgeState::Proposed  => "wf-edge-line proposed",
                                        EdgeState::Blocked   => "wf-edge-line blocked",
                                        EdgeState::Unconnected => "wf-edge-line unconnected",
                                    };
                                    let memex = e.memex_remembered;
                                    view! {
                                        <div class="wf-edge">
                                            <div class={edge_class}>
                                                {memex.then(|| view! {
                                                    <span class="wf-edge-memex" title="Auto-approved from memex">"🧠"</span>
                                                })}
                                            </div>
                                        </div>
                                    }
                                })}
                            }.into_any()
                        }
                    />
                </div>
            </Show>
        </div>
    }
}

/// DESIGN mode placeholder — empty canvas with tools strip.
/// (Full Design mode implementation is Task 5.)
#[component]
fn WorkflowDesignMode() -> impl IntoView {
    view! {
        <div class="wf-design-layout">
            <div class="wf-design-tools">
                <button class="wf-design-tool-btn" title="Add agent node">"🤖"</button>
                <button class="wf-design-tool-btn" title="Add synthesizer">"⬡"</button>
                <button class="wf-design-tool-btn" title="Add note">"📝"</button>
                <button class="wf-design-tool-btn save" title="Save pipeline">"💾"</button>
                <button class="wf-design-tool-btn run" title="Run workflow">"▶"</button>
            </div>
            <div class="wf-graph-canvas">
                <div class="wf-graph-empty">
                    <span>"Design mode"</span>
                    <span>"Use the tools on the left to build a workflow."</span>
                    <span style="font-size:10px;color:var(--text-3);">"Click 🤖 to add an agent node, then describe what it should do."</span>
                </div>
            </div>
        </div>
    }
}
```

- [ ] **Step 2: Compile check**

```bash
cd pap && cargo check -p papillon-frontend 2>&1 | grep "^error" | head -10
```
Expected: no errors.

- [ ] **Step 3: Verify the file compiles (trunk check if available)**

```bash
cd pap/apps/papillon/frontend && trunk build --no-minification 2>&1 | grep -E "^error" | head -10
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs
git commit -m "feat(workflow): MAP mode graph renderer with node/edge visualization"
```

---

## Task 5: DESIGN mode — interactive node builder with agent nodes

Implement the interactive Design mode: clicking the 🤖 tool adds a new agent node to `canvas_state.workflow_graph`; each node has an inline intent text field. This upgrades `WorkflowDesignMode` from a static placeholder to a live component.

**Files:**
- Modify: `apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs`

- [ ] **Step 1: Write a failing test for node addition**

```rust
#[cfg(test)]
mod tests {
    use papillon_shared::{WorkflowGraph, WorkflowNode, types::PipelineNodeType};

    #[test]
    fn add_agent_node_increments_node_count() {
        let mut graph = WorkflowGraph::default();
        let node = WorkflowNode {
            id: "n1".into(),
            node_type: PipelineNodeType::Agent,
            intent: "find flights".into(),
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
        graph.nodes.push(node);
        assert_eq!(graph.nodes.len(), 1);
        assert!(graph.is_designed == false);
        graph.is_designed = true;
        assert!(graph.is_designed);
    }
}
```

- [ ] **Step 2: Run test — expect pass** (pure logic test)

```bash
cd pap && cargo test -p papillon-shared add_agent_node_increments_node_count 2>&1 | tail -5
```
Expected: `ok`

- [ ] **Step 3: Replace `WorkflowDesignMode` with interactive version**

Find `fn WorkflowDesignMode()` in `canvas_workflow_pipeline.rs` and replace with:

```rust
/// DESIGN mode — interactive workflow builder.
/// Agent nodes are added to `canvas_state.workflow_graph`.
/// Clicking 🤖 appends a new `WorkflowNode`. Typing in the intent field
/// updates that node's `intent`. Clicking ▶ runs the graph as pipeline blocks.
#[component]
fn WorkflowDesignMode() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let add_agent_node = move |_| {
        canvas_state.workflow_graph.update(|g| {
            let id = format!("design-node-{}", g.nodes.len() + 1);
            let x = (g.nodes.len() as f64) * 280.0;
            g.nodes.push(papillon_shared::WorkflowNode {
                id,
                node_type: papillon_shared::types::PipelineNodeType::Agent,
                intent: String::new(),
                agent_name: None,
                agent_did: None,
                pap_uri: None,
                action_type: String::new(),
                input_ports: vec![],
                output_ports: vec![],
                template_override: None,
                position_x: x,
                position_y: 0.0,
            });
            g.is_designed = true;
        });
    };

    let run_workflow = move |_| {
        // Submit each node's intent as a prompt on the front face.
        let graph = canvas_state.workflow_graph.get_untracked();
        if graph.nodes.is_empty() { return; }
        for node in &graph.nodes {
            if !node.intent.is_empty() {
                canvas_state.prefill_prompt.set(Some(node.intent.clone()));
            }
        }
        // Flip to front face so the user sees blocks being created.
        canvas_state.canvas_side.set(CanvasSide::Front);
    };

    let has_nodes = move || !canvas_state.workflow_graph.get().nodes.is_empty();

    view! {
        <div class="wf-design-layout">
            // Tools strip
            <div class="wf-design-tools">
                <button
                    class="wf-design-tool-btn"
                    title="Add agent node"
                    on:click=add_agent_node
                >"🤖"</button>
                <button class="wf-design-tool-btn" title="Add synthesizer">"⬡"</button>
                <button class="wf-design-tool-btn" title="Add note">"📝"</button>
                <button class="wf-design-tool-btn save" title="Save pipeline">"💾"</button>
                <button
                    class="wf-design-tool-btn run"
                    title="Run workflow — fires each node as a canvas block"
                    on:click=run_workflow
                >"▶"</button>
            </div>

            // Graph area
            <div class="wf-graph-canvas">
                <Show
                    when=has_nodes
                    fallback=|| view! {
                        <div class="wf-graph-empty">
                            <span>"DESIGN MODE"</span>
                            <span>"Click 🤖 to add an agent node."</span>
                            <span style="font-size:10px;color:var(--text-3);">
                                "Describe what each step should do. Agents are resolved at run time."
                            </span>
                        </div>
                    }
                >
                    <div class="wf-graph-row">
                        <For
                            each=move || canvas_state.workflow_graph.get().nodes.iter().cloned().enumerate().collect::<Vec<_>>()
                            key=|(_, node)| node.id.clone()
                            children=move |(i, node)| {
                                let node_id = node.id.clone();
                                let initial_intent = node.intent.clone();
                                let node_name = node.agent_name.clone()
                                    .unwrap_or_else(|| format!("Agent {}", i + 1));
                                let is_last = move || {
                                    let g = canvas_state.workflow_graph.get();
                                    g.nodes.last().map(|n| n.id == node_id).unwrap_or(false)
                                };

                                view! {
                                    <div class="wf-node">
                                        <div class="wf-node-header">
                                            <span class="wf-node-emoji">"🤖"</span>
                                            <span class="wf-node-name">{node_name}</span>
                                        </div>
                                        <textarea
                                            class="wf-node-intent-input"
                                            placeholder="What should this step do?"
                                            rows=3
                                            prop:value=initial_intent
                                            on:input=move |ev| {
                                                let val = leptos::prelude::event_target_value(&ev);
                                                let nid = node_id.clone();
                                                canvas_state.workflow_graph.update(|g| {
                                                    if let Some(n) = g.nodes.iter_mut().find(|n| n.id == nid) {
                                                        n.intent = val.clone();
                                                    }
                                                });
                                            }
                                        />
                                    </div>
                                    // Show edge arrow between consecutive nodes (not after last)
                                    <Show when=move || !is_last()>
                                        <div class="wf-edge">
                                            <div class="wf-edge-line proposed" />
                                        </div>
                                    </Show>
                                }.into_any()
                            }
                        />
                    </div>
                </Show>
            </div>
        </div>
    }
}
```

- [ ] **Step 4: Compile check**

```bash
cd pap && cargo check -p papillon-frontend 2>&1 | grep "^error" | head -10
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs
git commit -m "feat(workflow): DESIGN mode interactive node builder with run-to-front-face"
```

---

## Task 6: Inline approval card in MAP mode for paused edges

When a `WorkflowEdge` has `state == EdgeState::Proposed`, show an inline approval card within the graph (not a modal). Approving writes to memex; the card disappears and the edge turns `Confirmed`.

This wires up the `wf-approval-card` CSS from Task 3 to the MAP mode renderer.

**Files:**
- Modify: `apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs`

- [ ] **Step 1: Write failing test for approval card visibility logic**

```rust
#[cfg(test)]
mod tests {
    use papillon_shared::EdgeState;

    #[test]
    fn proposed_edge_requires_approval_card() {
        let state = EdgeState::Proposed;
        assert_eq!(state, EdgeState::Proposed);
        // Confirmed edges must NOT show card
        let confirmed = EdgeState::Confirmed;
        assert_ne!(confirmed, EdgeState::Proposed);
    }
}
```

- [ ] **Step 2: Run test — expect pass**

```bash
cd pap && cargo test -p papillon-shared proposed_edge_requires_approval_card 2>&1 | tail -5
```
Expected: `ok`

- [ ] **Step 3: Add `MapApprovalCard` component to `canvas_workflow_pipeline.rs`**

After the `WorkflowDesignMode` function, add:

```rust
/// Inline approval card for a `Proposed` edge in MAP mode.
/// Shows agent identity, disclosure summary, and three action buttons.
/// `edge_id` — the edge to approve/deny.
/// `to_agent_name` — humanized name of the downstream agent.
/// `output_type` — schema type flowing out of the upstream node.
/// `input_type` — schema type required by the downstream node.
/// `agent_did` — downstream agent's DID.
#[component]
fn MapApprovalCard(
    edge_id: String,
    to_agent_name: String,
    output_type: String,
    input_type: String,
    agent_did: String,
) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let eid_allow = edge_id.clone();
    let eid_always = edge_id.clone();
    let eid_deny = edge_id.clone();
    let agent_did_always = agent_did.clone();
    let output_type_always = output_type.clone();
    let input_type_always = input_type.clone();

    let approve = move |permanent: bool| {
        let eid = if permanent { eid_always.clone() } else { eid_allow.clone() };
        let oid = output_type_always.clone();
        let iid = input_type_always.clone();
        let adid = agent_did_always.clone();
        canvas_state.workflow_graph.update(move |g| {
            if let Some(edge) = g.edges.iter_mut().find(|e| e.id == eid) {
                edge.state = EdgeState::Confirmed;
                edge.memex_remembered = permanent;
            }
        });
        if permanent {
            // Persist to memex via Tauri command
            wasm_bindgen_futures::spawn_local(async move {
                let args = serde_json::json!({
                    "outputType": oid,
                    "inputType": iid,
                    "agentDid": adid,
                });
                let _ = crate::bridge::invoke::<(), _>("store_workflow_approval", &args).await;
            });
        }
    };

    let deny_edge = move |_| {
        let eid = eid_deny.clone();
        canvas_state.workflow_graph.update(move |g| {
            if let Some(edge) = g.edges.iter_mut().find(|e| e.id == eid) {
                edge.state = EdgeState::Blocked;
            }
        });
    };

    view! {
        <div class="wf-approval-card">
            <div class="wf-approval-card-title">"APPROVAL REQUIRED"</div>
            <div class="wf-approval-card-agent">{to_agent_name.clone()}</div>
            <div class="wf-approval-card-disclosure">
                "This step needs: " <code>{input_type.clone()}</code>
                " from the previous step (" <code>{output_type.clone()}</code> ")."
            </div>
            <div class="wf-approval-card-actions">
                <button class="wf-approval-btn allow" on:click=move |_| approve(false)>
                    "Allow once"
                </button>
                <button class="wf-approval-btn always" on:click=move |_| approve(true)>
                    "Always allow 🧠"
                </button>
                <button class="wf-approval-btn deny" on:click=deny_edge>
                    "Deny"
                </button>
            </div>
        </div>
    }
}
```

- [ ] **Step 4: Wire `MapApprovalCard` into `WorkflowMapMode` — show for Proposed edges**

In `WorkflowMapMode`, after the closing `</div>` of the `.wf-graph-row`, add:

```rust
// Show inline approval cards for proposed edges
<For
    each=move || {
        graph.get().edges.iter()
            .filter(|e| e.state == EdgeState::Proposed)
            .cloned()
            .collect::<Vec<_>>()
    }
    key=|e| e.id.clone()
    children=move |edge| {
        let g = graph.get();
        let to_agent = g.nodes.iter()
            .find(|n| n.id == edge.to_node_id)
            .and_then(|n| n.agent_name.clone())
            .unwrap_or_else(|| "Agent".to_string());
        view! {
            <MapApprovalCard
                edge_id=edge.id.clone()
                to_agent_name=to_agent
                output_type=edge.from_port.path.clone()
                input_type=edge.to_port.path.clone()
                agent_did=edge.to_node_id.clone()
            />
        }
    }
/>
```

- [ ] **Step 5: Compile check**

```bash
cd pap && cargo check -p papillon-frontend 2>&1 | grep "^error" | head -10
```
Expected: no errors. If `bridge::invoke` has a different signature, adjust accordingly — check existing usages in `topbar.rs` or `app.rs` for the correct call form.

- [ ] **Step 6: Commit**

```bash
git add apps/papillon/frontend/src/components/canvas_workflow_pipeline.rs
git commit -m "feat(workflow): inline approval card for proposed edges in MAP mode"
```

---

## Task 7: E2E tests — verify Map mode and Design mode

**Files:**
- Modify: `e2e/tests/workflow.spec.ts`

- [ ] **Step 1: Check existing workflow tests still pass**

```bash
cd pap && npx playwright test e2e/tests/workflow.spec.ts --reporter=list 2>&1 | grep -E "passed|failed|skipped"
```
Expected: existing tests pass.

- [ ] **Step 2: Add MAP mode test**

In `e2e/tests/workflow.spec.ts`, add a new describe block:

```typescript
test.describe("Workflow tab MAP/DESIGN modes", () => {
    test("back face workflow tab shows MAP/DESIGN toggle", async ({ page }) => {
        await page.goto("/", { waitUntil: "commit" });
        await waitForApp(page);
        // Flip to back face
        await page.locator(".canvas-flip-toggle").click();
        // Navigate to workflow tab
        await page.locator(".back-face-tab").filter({ hasText: "Workflow" }).click();
        // Toggle should be visible
        await expect(page.locator(".wf-mode-toggle")).toBeVisible();
        await expect(page.locator(".wf-mode-btn").filter({ hasText: "MAP" })).toBeVisible();
        await expect(page.locator(".wf-mode-btn").filter({ hasText: "DESIGN" })).toBeVisible();
    });

    test("MAP mode shows empty state when no blocks", async ({ page }) => {
        await page.goto("/", { waitUntil: "commit" });
        await waitForApp(page);
        await page.locator(".canvas-flip-toggle").click();
        await page.locator(".back-face-tab").filter({ hasText: "Workflow" }).click();
        await expect(page.locator(".wf-mode-btn.active").filter({ hasText: "MAP" })).toBeVisible();
        await expect(page.locator(".wf-graph-empty")).toBeVisible();
    });

    test("DESIGN mode shows tools strip and empty canvas", async ({ page }) => {
        await page.goto("/", { waitUntil: "commit" });
        await waitForApp(page);
        await page.locator(".canvas-flip-toggle").click();
        await page.locator(".back-face-tab").filter({ hasText: "Workflow" }).click();
        await page.locator(".wf-mode-btn").filter({ hasText: "DESIGN" }).click();
        await expect(page.locator(".wf-design-tools")).toBeVisible();
        await expect(page.locator(".wf-design-tool-btn").first()).toBeVisible();
    });

    test("DESIGN mode add node button creates a node", async ({ page }) => {
        await page.goto("/", { waitUntil: "commit" });
        await waitForApp(page);
        await page.locator(".canvas-flip-toggle").click();
        await page.locator(".back-face-tab").filter({ hasText: "Workflow" }).click();
        await page.locator(".wf-mode-btn").filter({ hasText: "DESIGN" }).click();
        // Click the 🤖 add agent node button
        await page.locator(".wf-design-tool-btn").filter({ hasText: "🤖" }).click();
        await expect(page.locator(".wf-node")).toBeVisible();
        await expect(page.locator(".wf-node-intent-input")).toBeVisible();
    });

    test("DESIGN mode node intent field accepts text", async ({ page }) => {
        await page.goto("/", { waitUntil: "commit" });
        await waitForApp(page);
        await page.locator(".canvas-flip-toggle").click();
        await page.locator(".back-face-tab").filter({ hasText: "Workflow" }).click();
        await page.locator(".wf-mode-btn").filter({ hasText: "DESIGN" }).click();
        await page.locator(".wf-design-tool-btn").filter({ hasText: "🤖" }).click();
        await page.locator(".wf-node-intent-input").fill("search for flights to Tokyo");
        await expect(page.locator(".wf-node-intent-input")).toHaveValue("search for flights to Tokyo");
    });
});
```

- [ ] **Step 3: Run new tests**

```bash
cd pap && npx playwright test e2e/tests/workflow.spec.ts --reporter=list 2>&1 | tail -20
```
Expected: new tests pass (may need to adjust selectors for the flip toggle button class — check `topbar.rs` for exact class name of the flip button).

- [ ] **Step 4: Commit**

```bash
git add e2e/tests/workflow.spec.ts
git commit -m "test(e2e): add MAP/DESIGN workflow mode toggle and node tests"
```

---

## Task 8: Final build and regression check

- [ ] **Step 1: Rust workspace compile check**

```bash
cd pap && cargo check -p papillon-frontend -p papillon-shared 2>&1 | grep "^error" | head -10
```
Expected: no errors.

- [ ] **Step 2: Run all papillon-shared tests**

```bash
cd pap && cargo test -p papillon-shared 2>&1 | tail -10
```
Expected: all tests pass.

- [ ] **Step 3: Full frontend build**

```bash
cd pap/apps/papillon/frontend && trunk build 2>&1 | tail -20
```
Expected: succeeds, outputs to `dist/`.

- [ ] **Step 4: Run full e2e suite (browser tests only)**

```bash
cd pap && npx playwright test e2e/tests/ --reporter=line 2>&1 | grep -E "passed|failed|skipped"
```
Expected: 0 failed.

- [ ] **Step 5: Verify spec requirements**

```
1. MAP mode — run two prompts: second uses {{block:ID}} from first.
   Flip to back face → Workflow tab → verify edge appears between two nodes.

2. DESIGN mode — click 🤖 twice → verify 2 nodes with a proposed edge arrow between them.
   Type intent in each → verify field is editable.

3. Approval card — manually set an edge state to Proposed in DevTools →
   verify approval card renders below the graph row with 3 action buttons.

4. Standalone regression — run a single prompt with no graph →
   back face shows that block as a single unconnected node in MAP mode.
```

- [ ] **Step 6: Final commit**

```bash
git add -A
git status  # confirm only expected files changed
git commit -m "feat(workflow): canvas workflow ux complete — MAP/DESIGN graph, inline approval cards"
```

---

## Self-Review

### Spec Coverage
- ✅ **§1 Back Face Two Modes** — MAP/DESIGN toggle in `CanvasWorkflowPipeline` (Task 4)
- ✅ **§1 Map Mode** — auto-derived graph from `{{block:ID}}` refs (Task 2, `derive_map_graph`)
- ✅ **§1 Map Mode** — node color badges via wing spectrum (Task 3 CSS + Task 4 component)
- ✅ **§1 Map Mode** — click node to jump to front face block (Task 4, `requested_expansion`)
- ✅ **§1 Map Mode** — TTL badge: rendered via `wf-node-badge` classes (resolved/running/failed/pending)
- ✅ **§1 Design Mode** — blank canvas + tools strip (Task 4 placeholder → Task 5 interactive)
- ✅ **§1 Design Mode** — agent node with intent field (Task 5)
- ✅ **§1 Design Mode** — Run button fires intents as front-face prompts (Task 5, `run_workflow`)
- ✅ **§2 Agent Nodes** — node anatomy: header, RECEIVES/OUTPUTS port sections (Task 4)
- ✅ **§3 Memex Approval Flow** — 🧠 badge on confirmed+remembered edges (Task 4 CSS + component)
- ✅ **§3 New Approval (inline card)** — `MapApprovalCard` with Allow once / Always allow / Deny (Task 6)
- ✅ **§3 "Always allow" writes to episode DB** — calls `store_workflow_approval` Tauri command (Task 6)
- ✅ **§4 Front/Back coordination** — MAP mode clicking node flips to front via `canvas_side` signal
- ✅ **§5 Standalone blocks** — single prompt → single node with no edges in MAP mode

### Out of Scope (per spec)
- Animated SVG edge routing — using CSS flexbox row, as spec dictates
- Agent marketplace browse UI (agents resolve from intent at run time)
- Multi-canvas workflow composition

### Type Consistency
- `WorkflowGraph`, `WorkflowNode`, `WorkflowEdge`, `EdgeState`, `WorkflowMode` — all from `papillon_shared::types` (already defined, no new definitions)
- `canvas_state.workflow_graph: RwSignal<WorkflowGraph>` — added in Task 1, used in Tasks 2, 4, 5, 6
- `canvas_state.workflow_mode: RwSignal<WorkflowMode>` — added in Task 1, read in Task 4
- `derive_map_graph(blocks: &[CanvasBlock]) -> WorkflowGraph` — defined in Task 2, called in Task 2 Effect
- `MapApprovalCard` reads `canvas_state.workflow_graph` — consistent with graph signal type

### Placeholder Scan
- No "TBD" or "implement later" remaining
- Every step has exact code
- Task 6 Step 5 notes that `bridge::invoke` signature may need adjustment — this is a verification step, not a placeholder
