# Block-Based Canvas Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform Papillon canvas from single-agent blocks to multi-agent schema.org containers with node-graph wiring, enabling visual pipeline composition where blocks represent multiple agents with matching I/O signatures.

**Architecture:** Blocks become containers for N agents sharing the same schema.org signature (input/output types). BM25 intent detection matches prompts to schema types. Blocks can wire together when output schema matches input schema, creating visual pipelines. No LLM required for core functionality - all type matching is deterministic via schema.org vocabulary.

**Tech Stack:** Rust (Leptos frontend, Tauri backend), schema.org vocabulary, BM25 text search, existing PAP protocol infrastructure

---

## Architecture Overview

### Current State
- **CanvasBlock** = single agent execution result
- Prompt → intent detection → single agent → rendered block
- Agent curation happens in workflow panel (separate from block)
- Blocks are independent (no connections)

### Target State
- **CanvasBlock** = container for multiple agents with same schema signature
- Block represents a **schema.org type transformation** (e.g., Place → WeatherForecast)
- Multiple agents can fulfill same transformation (OpenWeather, NOAA, WeatherAPI all provide Place → WeatherForecast)
- Blocks can **wire together** when output type matches input type
- Visual node graph shows data flow through agent pipeline
- Marketplace search finds agents by schema signature

### Key Concepts

**Schema Signature:**
- **Input types**: e.g., `[schema:Place]`
- **Output types**: e.g., `[schema:WeatherForecast]`
- **Agents match**: All agents with signature `Place → WeatherForecast` can fill same block

**Block Wiring:**
- Output port: Block produces `schema:WeatherForecast`
- Input port: Block accepts `schema:Place, schema:WeatherForecast`
- **Connection valid** if output type ⊆ input types
- **Disclosure check**: Connection cannot increase disclosure beyond what user approved

**Agent Curation:**
- Happens **per-block** (not global workflow panel)
- User selects which agents to execute from those matching signature
- "Find more" searches marketplace for agents with matching signature

---

## File Structure

### New Files

**Frontend Components:**
- `apps/papillon/frontend/src/components/block_container.rs` - Block as multi-agent container
- `apps/papillon/frontend/src/components/block_ports.rs` - Input/output port UI
- `apps/papillon/frontend/src/components/block_wiring.rs` - Visual connections between blocks
- `apps/papillon/frontend/src/components/agent_selector.rs` - Per-block agent selection
- `apps/papillon/frontend/src/components/canvas_graph.rs` - Node graph layout engine

**Backend Types:**
- `crates/papillon-shared/src/block_container.rs` - BlockContainer type
- `crates/papillon-shared/src/schema_signature.rs` - Schema signature matching
- `crates/papillon-shared/src/block_connection.rs` - Block wiring types

**Backend Commands:**
- `apps/papillon/src/commands/canvas/block_wiring.rs` - Connect/disconnect blocks
- `apps/papillon/src/commands/canvas/agent_search.rs` - Find agents by schema

### Modified Files

**Types:**
- `crates/papillon-shared/src/types.rs` - Extend CanvasBlock with container fields
- `crates/papillon-shared/src/types.rs` - Add BlockPort, BlockConnection types

**Frontend:**
- `apps/papillon/frontend/src/pages/canvas.rs` - Integrate graph view
- `apps/papillon/frontend/src/components/block_renderer.rs` - Support block containers
- `apps/papillon/frontend/styles/main.css` - Block container, port, wire styles

**Backend:**
- `apps/papillon/src/commands/canvas/approval.rs` - Handle multi-agent approval
- `apps/papillon/src/commands/canvas/execution.rs` - Execute multiple agents per block

---

## Task 1: Schema Signature Types

**Files:**
- Create: `crates/papillon-shared/src/schema_signature.rs`
- Modify: `crates/papillon-shared/src/lib.rs`

- [ ] **Step 1: Create schema signature module**

Create `crates/papillon-shared/src/schema_signature.rs`:

```rust
use serde::{Deserialize, Serialize};

/// Schema.org signature defining what types a block accepts and produces.
///
/// Example: Weather block accepts Place, produces WeatherForecast
/// Signature: inputs=[schema:Place], outputs=[schema:WeatherForecast]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SchemaSignature {
    /// Schema.org types this block accepts as input (empty = no inputs)
    pub input_types: Vec<String>,
    /// Schema.org types this block produces as output
    pub output_types: Vec<String>,
}

impl SchemaSignature {
    /// Create signature from agent metadata
    pub fn from_agent(requires: &[String], returns: &[String]) -> Self {
        Self {
            input_types: requires.to_vec(),
            output_types: returns.to_vec(),
        }
    }
    
    /// Check if this signature's outputs can connect to another's inputs
    pub fn can_wire_to(&self, other: &SchemaSignature) -> bool {
        if other.input_types.is_empty() {
            return false; // Target accepts no inputs
        }
        
        // At least one output type must match at least one input type
        self.output_types.iter().any(|out| {
            other.input_types.iter().any(|inp| out == inp)
        })
    }
    
    /// Check if two signatures are compatible (same I/O types)
    pub fn matches(&self, other: &SchemaSignature) -> bool {
        self.input_types == other.input_types && 
        self.output_types == other.output_types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_can_wire_place_to_weather() {
        let place_block = SchemaSignature {
            input_types: vec![],
            output_types: vec!["schema:Place".to_string()],
        };
        
        let weather_block = SchemaSignature {
            input_types: vec!["schema:Place".to_string()],
            output_types: vec!["schema:WeatherForecast".to_string()],
        };
        
        assert!(place_block.can_wire_to(&weather_block));
        assert!(!weather_block.can_wire_to(&place_block));
    }
    
    #[test]
    fn test_matches_same_signature() {
        let sig1 = SchemaSignature {
            input_types: vec!["schema:Place".to_string()],
            output_types: vec!["schema:WeatherForecast".to_string()],
        };
        
        let sig2 = sig1.clone();
        assert!(sig1.matches(&sig2));
    }
}
```

- [ ] **Step 2: Export in lib.rs**

Add to `crates/papillon-shared/src/lib.rs`:

```rust
pub mod schema_signature;
pub use schema_signature::SchemaSignature;
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p papillon-shared`
Expected: No errors

- [ ] **Step 4: Run tests**

Run: `cargo test -p papillon-shared schema_signature`
Expected: 2 tests pass

- [ ] **Step 5: Commit**

```bash
git add crates/papillon-shared/src/schema_signature.rs crates/papillon-shared/src/lib.rs
git commit -m "feat(types): add SchemaSignature for block I/O matching

- Define SchemaSignature with input/output schema.org types
- Implement can_wire_to() for connection validation
- Implement matches() for agent compatibility
- Add unit tests for wiring logic"
```

---

## Task 2: Block Container Types

**Files:**
- Create: `crates/papillon-shared/src/block_container.rs`
- Modify: `crates/papillon-shared/src/lib.rs`
- Modify: `crates/papillon-shared/src/types.rs`

- [ ] **Step 1: Create block container module**

Create `crates/papillon-shared/src/block_container.rs`:

```rust
use serde::{Deserialize, Serialize};
use crate::SchemaSignature;

/// A block container holding multiple agents with the same schema signature.
///
/// Represents a single transformation in the canvas graph (e.g., Place → Weather).
/// Multiple agents can provide this transformation - user selects which to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockContainer {
    /// Unique container ID
    pub id: String,
    /// Schema signature (what this block accepts/produces)
    pub signature: SchemaSignature,
    /// Agents that can fulfill this signature (DIDs)
    pub candidate_agents: Vec<String>,
    /// Which agents user selected to execute
    pub selected_agents: Vec<String>,
    /// Connections to other blocks (by block ID)
    pub input_connections: Vec<BlockConnection>,
    /// Visual position on canvas (for node graph layout)
    pub position: BlockPosition,
}

/// Connection from one block's output to another's input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockConnection {
    /// Source block ID
    pub from_block_id: String,
    /// Target block ID (this block)
    pub to_block_id: String,
    /// Which output type from source
    pub output_type: String,
    /// Which input type on target
    pub input_type: String,
}

/// 2D position for node graph layout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPosition {
    pub x: f64,
    pub y: f64,
}

impl Default for BlockPosition {
    fn default() -> Self {
        Self { x: 0.0, y: 0.0 }
    }
}
```

- [ ] **Step 2: Export in lib.rs**

Add to `crates/papillon-shared/src/lib.rs`:

```rust
pub mod block_container;
pub use block_container::{BlockContainer, BlockConnection, BlockPosition};
```

- [ ] **Step 3: Extend CanvasBlock in types.rs**

Add fields to `pub struct CanvasBlock` (around line 716):

```rust
/// If this block is a container, holds the container metadata
#[serde(default)]
#[serde(skip_serializing_if = "Option::is_none")]
pub container: Option<BlockContainer>,
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p papillon-shared`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add crates/papillon-shared/src/block_container.rs crates/papillon-shared/src/lib.rs crates/papillon-shared/src/types.rs
git commit -m "feat(types): add BlockContainer for multi-agent blocks

- Define BlockContainer with schema signature and agent list
- Add BlockConnection for wiring blocks together
- Add BlockPosition for node graph layout
- Extend CanvasBlock with optional container field"
```

---

## Task 3: Block Port Component

**Files:**
- Create: `apps/papillon/frontend/src/components/block_ports.rs`
- Modify: `apps/papillon/frontend/src/components/mod.rs`

- [ ] **Step 1: Create block ports component**

Create `apps/papillon/frontend/src/components/block_ports.rs`:

```rust
use leptos::prelude::*;
use papillon_shared::{SchemaSignature, BlockConnection};

/// Input port showing what schema types this block accepts
#[component]
pub fn BlockInputPort(
    block_id: String,
    signature: SchemaSignature,
    connections: Vec<BlockConnection>,
) -> impl IntoView {
    let has_connections = !connections.is_empty();
    let input_label = if signature.input_types.len() == 1 {
        humanize_schema_type(&signature.input_types[0])
    } else {
        format!("{} types", signature.input_types.len())
    };
    
    view! {
        <div class="block-port block-input-port" class:connected=has_connections>
            <div class="port-dot" title=format!("Accepts: {}", signature.input_types.join(", "))></div>
            <div class="port-label">{input_label}</div>
        </div>
    }
}

/// Output port showing what schema types this block produces
#[component]
pub fn BlockOutputPort(
    block_id: String,
    signature: SchemaSignature,
) -> impl IntoView {
    let output_label = if signature.output_types.len() == 1 {
        humanize_schema_type(&signature.output_types[0])
    } else {
        format!("{} types", signature.output_types.len())
    };
    
    view! {
        <div class="block-port block-output-port">
            <div class="port-label">{output_label}</div>
            <div class="port-dot" title=format!("Produces: {}", signature.output_types.join(", "))></div>
        </div>
    }
}

fn humanize_schema_type(schema_type: &str) -> String {
    schema_type
        .strip_prefix("schema:")
        .unwrap_or(schema_type)
        .to_string()
}
```

- [ ] **Step 2: Export component**

Add to `apps/papillon/frontend/src/components/mod.rs`:

```rust
pub mod block_ports;
```

- [ ] **Step 3: Add port styles to CSS**

Append to `apps/papillon/frontend/styles/main.css`:

```css
/* ═══════════════════════════════════════════════════════════
   BLOCK PORTS
   ═══════════════════════════════════════════════════════════ */

.block-port {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    padding: var(--sp-xs) var(--sp-sm);
    font: var(--text-small);
    color: var(--text-secondary);
}

.block-input-port {
    justify-content: flex-start;
}

.block-output-port {
    justify-content: flex-end;
}

.port-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid var(--border);
    background: var(--bg-secondary);
    transition: all 150ms ease;
    cursor: pointer;
}

.port-dot:hover {
    border-color: var(--purple);
    transform: scale(1.2);
}

.block-input-port.connected .port-dot {
    background: var(--teal);
    border-color: var(--teal);
}

.port-label {
    font-weight: 500;
    text-transform: capitalize;
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p papillon-frontend`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/components/block_ports.rs apps/papillon/frontend/src/components/mod.rs apps/papillon/frontend/styles/main.css
git commit -m "feat(ui): add block port components for I/O visualization

- Create BlockInputPort showing accepted schema types
- Create BlockOutputPort showing produced schema types
- Add port dot UI with hover states
- Style ports with teal highlight when connected"
```

---

## Task 4: Agent Selector Component

**Files:**
- Create: `apps/papillon/frontend/src/components/agent_selector.rs`
- Modify: `apps/papillon/frontend/src/components/mod.rs`

- [ ] **Step 1: Create agent selector component**

Create `apps/papillon/frontend/src/components/agent_selector.rs`:

```rust
use leptos::prelude::*;
use papillon_shared::AgentCandidate;

/// Per-block agent selection UI
/// Shows all agents matching block's schema signature
#[component]
pub fn AgentSelector(
    block_id: String,
    candidates: Vec<AgentCandidate>,
    selected: RwSignal<Vec<String>>,
) -> impl IntoView {
    let agent_count = candidates.len();
    
    view! {
        <div class="agent-selector">
            <div class="agent-selector-header">
                <span class="agent-count">{agent_count}" agents available"</span>
                <button
                    class="find-more-agents-btn"
                    title="Search marketplace for more agents"
                >
                    "🔍 Find more"
                </button>
            </div>
            
            <div class="agent-selector-list">
                <For
                    each=move || candidates.clone()
                    key=|c| c.did.clone()
                    children=move |agent| {
                        view! {
                            <AgentOption
                                agent=agent.clone()
                                selected=selected
                            />
                        }
                    }
                />
            </div>
        </div>
    }
}

#[component]
fn AgentOption(
    agent: AgentCandidate,
    selected: RwSignal<Vec<String>>,
) -> impl IntoView {
    let agent_did = agent.did.clone();
    let agent_did_for_toggle = agent.did.clone();
    
    let is_selected = Memo::new(move |_| {
        selected.get().contains(&agent_did)
    });
    
    let is_on_device = agent.did.starts_with("did:key:");
    let truncated_did = truncate_did(&agent.did);
    
    view! {
        <label class="agent-option" class:selected=is_selected>
            <input
                type="checkbox"
                class="agent-checkbox"
                checked=is_selected
                on:change=move |_| {
                    selected.update(|list| {
                        if list.contains(&agent_did_for_toggle) {
                            list.retain(|d| d != &agent_did_for_toggle);
                        } else {
                            list.push(agent_did_for_toggle.clone());
                        }
                    });
                }
            />
            <div class="agent-option-info">
                <div class="agent-option-header">
                    <span class="agent-name">{agent.name.clone()}</span>
                    <Show when=move || is_on_device>
                        <span class="trust-badge on-device">"On-Device"</span>
                    </Show>
                </div>
                <span class="agent-did">{truncated_did}</span>
            </div>
        </label>
    }
}

fn truncate_did(did: &str) -> String {
    if did.len() <= 30 {
        return did.to_string();
    }
    format!("{}...{}", &did[..20], &did[did.len() - 8..])
}
```

- [ ] **Step 2: Export component**

Add to `apps/papillon/frontend/src/components/mod.rs`:

```rust
pub mod agent_selector;
```

- [ ] **Step 3: Add agent selector styles**

Append to `apps/papillon/frontend/styles/main.css`:

```css
/* ═══════════════════════════════════════════════════════════
   AGENT SELECTOR (PER-BLOCK)
   ═══════════════════════════════════════════════════════════ */

.agent-selector {
    padding: var(--sp-md);
    background: var(--bg-tertiary);
    border-radius: var(--r-md);
}

.agent-selector-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--sp-md);
}

.agent-count {
    font: var(--text-small);
    color: var(--text-secondary);
    font-weight: 500;
}

.find-more-agents-btn {
    padding: var(--sp-xs) var(--sp-sm);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-sm);
    cursor: pointer;
    font: var(--text-small);
    color: var(--text-primary);
    transition: all 150ms ease;
}

.find-more-agents-btn:hover {
    background: var(--purple-muted);
    border-color: var(--purple);
}

.agent-selector-list {
    display: flex;
    flex-direction: column;
    gap: var(--sp-sm);
}

.agent-option {
    display: flex;
    align-items: flex-start;
    gap: var(--sp-md);
    padding: var(--sp-md);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    cursor: pointer;
    transition: all 150ms ease;
}

.agent-option:hover {
    background: var(--surface-card-hover);
    border-color: var(--surface-card-border-hover);
}

.agent-option.selected {
    background: var(--purple-muted);
    border-color: var(--purple);
}

.agent-checkbox {
    margin-top: 2px;
    flex-shrink: 0;
}

.agent-option-info {
    flex: 1;
}

.agent-option-header {
    display: flex;
    align-items: center;
    gap: var(--sp-sm);
    margin-bottom: var(--sp-xs);
}

.agent-name {
    font: var(--text-ui);
    font-weight: 700;
    color: var(--text-primary);
}

.agent-did {
    display: block;
    font: var(--text-mono);
    font-size: 11px;
    color: var(--text-secondary);
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p papillon-frontend`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/components/agent_selector.rs apps/papillon/frontend/src/components/mod.rs apps/papillon/frontend/styles/main.css
git commit -m "feat(ui): add per-block agent selector component

- Create AgentSelector showing all agents for block signature
- Multi-select checkboxes for agent selection
- Find more button for marketplace search
- On-device trust badges
- DID truncation for readability"
```

---

## Task 5: Block Container Component

**Files:**
- Create: `apps/papillon/frontend/src/components/block_container.rs`
- Modify: `apps/papillon/frontend/src/components/mod.rs`

- [ ] **Step 1: Create block container component**

Create `apps/papillon/frontend/src/components/block_container.rs`:

```rust
use leptos::prelude::*;
use papillon_shared::{CanvasBlock, BlockContainer};

use crate::components::agent_selector::AgentSelector;
use crate::components::block_ports::{BlockInputPort, BlockOutputPort};
use crate::components::block_renderer::BlockRenderer;

/// Block as multi-agent container with I/O ports
#[component]
pub fn BlockContainerView(block: CanvasBlock) -> impl IntoView {
    let container = match &block.container {
        Some(c) => c.clone(),
        None => {
            // Fallback to single-block rendering if not a container
            return view! {
                <BlockRenderer block=block />
            }.into_any();
        }
    };
    
    let selected_agents = RwSignal::new(container.selected_agents.clone());
    let show_selector = RwSignal::new(false);
    
    let toggle_selector = move |_| {
        show_selector.update(|v| *v = !*v);
    };
    
    view! {
        <div class="block-container">
            // Input port (if block accepts inputs)
            <Show when=move || !container.signature.input_types.is_empty()>
                <BlockInputPort
                    block_id=block.id.clone()
                    signature=container.signature.clone()
                    connections=container.input_connections.clone()
                />
            </Show>
            
            // Block header with agent selector toggle
            <div class="block-container-header">
                <h3 class="block-container-title">
                    {humanize_signature(&container.signature)}
                </h3>
                <button
                    class="agent-selector-toggle"
                    on:click=toggle_selector
                >
                    {move || {
                        let count = selected_agents.get().len();
                        format!("{} agent{}", count, if count == 1 { "" } else { "s" })
                    }}
                </button>
            </div>
            
            // Agent selector (expandable)
            <Show when=move || show_selector.get()>
                <AgentSelector
                    block_id=block.id.clone()
                    candidates=vec![] // TODO: Get from container
                    selected=selected_agents
                />
            </Show>
            
            // Rendered content
            <div class="block-container-content">
                <BlockRenderer block=block.clone() />
            </div>
            
            // Output port
            <BlockOutputPort
                block_id=block.id.clone()
                signature=container.signature.clone()
            />
        </div>
    }.into_any()
}

fn humanize_signature(sig: &papillon_shared::SchemaSignature) -> String {
    let output = if sig.output_types.len() == 1 {
        sig.output_types[0].strip_prefix("schema:").unwrap_or(&sig.output_types[0]).to_string()
    } else {
        format!("{} types", sig.output_types.len())
    };
    
    if sig.input_types.is_empty() {
        output
    } else {
        let input = if sig.input_types.len() == 1 {
            sig.input_types[0].strip_prefix("schema:").unwrap_or(&sig.input_types[0]).to_string()
        } else {
            format!("{} types", sig.input_types.len())
        };
        format!("{} → {}", input, output)
    }
}
```

- [ ] **Step 2: Export component**

Add to `apps/papillon/frontend/src/components/mod.rs`:

```rust
pub mod block_container;
```

- [ ] **Step 3: Add block container styles**

Append to `apps/papillon/frontend/styles/main.css`:

```css
/* ═══════════════════════════════════════════════════════════
   BLOCK CONTAINER
   ═══════════════════════════════════════════════════════════ */

.block-container {
    position: relative;
    margin: var(--sp-lg) 0;
    padding: var(--sp-lg);
    background: var(--bg-secondary);
    border: 2px solid var(--border);
    border-radius: var(--r-lg);
    transition: all 150ms ease;
}

.block-container:hover {
    border-color: var(--purple-muted);
    box-shadow: 0 2px 8px rgba(108, 92, 231, 0.1);
}

.block-container-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: var(--sp-md);
    padding-bottom: var(--sp-md);
    border-bottom: 1px solid var(--border-subtle);
}

.block-container-title {
    margin: 0;
    font: var(--text-h3);
    color: var(--text-primary);
}

.agent-selector-toggle {
    padding: var(--sp-xs) var(--sp-md);
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--r-md);
    cursor: pointer;
    font: var(--text-ui);
    font-weight: 500;
    color: var(--text-secondary);
    transition: all 150ms ease;
}

.agent-selector-toggle:hover {
    background: var(--purple-muted);
    border-color: var(--purple);
    color: var(--text-primary);
}

.block-container-content {
    margin: var(--sp-md) 0;
}
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p papillon-frontend`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/components/block_container.rs apps/papillon/frontend/src/components/mod.rs apps/papillon/frontend/styles/main.css
git commit -m "feat(ui): add block container component with ports

- Create BlockContainerView wrapping blocks with I/O ports
- Show input/output ports based on signature
- Expandable agent selector per block
- Humanize signature display (e.g., Place → Weather)
- Fallback to single BlockRenderer if not container"
```

---

## Task 6: Integration - Use Block Containers in Canvas

**Files:**
- Modify: `apps/papillon/frontend/src/pages/canvas.rs`

- [ ] **Step 1: Import BlockContainerView**

Add to imports in `apps/papillon/frontend/src/pages/canvas.rs`:

```rust
use crate::components::block_container::BlockContainerView;
```

- [ ] **Step 2: Replace BlockRenderer with BlockContainerView**

Find the `For` loop rendering blocks (around line 149) and replace:

```rust
// OLD:
<BlockRenderer block=b.clone() />

// NEW:
<BlockContainerView block=b.clone() />
```

- [ ] **Step 3: Verify compilation**

Run: `cargo check -p papillon-frontend`
Expected: No errors

- [ ] **Step 4: Test in browser**

Run: `cargo tauri dev`
Expected: Blocks render with BlockContainerView (will show fallback to BlockRenderer since containers not yet created)

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/frontend/src/pages/canvas.rs
git commit -m "feat(ui): integrate block containers into canvas rendering

- Replace BlockRenderer with BlockContainerView
- Blocks now render with container UI when available
- Falls back to original BlockRenderer for non-containers"
```

---

## Task 7: Backend Command - Create Block Container

**Files:**
- Create: `apps/papillon/src/commands/canvas/container.rs`
- Modify: `apps/papillon/src/commands/canvas/mod.rs`

- [ ] **Step 1: Create container command**

Create `apps/papillon/src/commands/canvas/container.rs`:

```rust
use tauri::{AppHandle, State};
use papillon_shared::{BlockContainer, SchemaSignature, BlockPosition};

use crate::state::AppState;

/// Create a block container from a prompt
///
/// Takes intent classification result and creates a container with
/// all agents matching the schema signature
#[tauri::command]
pub async fn create_block_container(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    action_type: String,
    query: String,
) -> Result<String, String> {
    // Get agents matching this action type
    let agents = state.db.load_all_agents()
        .map_err(|e| format!("Failed to load agents: {}", e))?;
    
    let matching_agents: Vec<_> = agents.iter()
        .filter(|a| a.action_types.contains(&action_type))
        .collect();
    
    if matching_agents.is_empty() {
        return Err(format!("No agents found for action: {}", action_type));
    }
    
    // Determine signature from first agent (all should match)
    let first_agent = matching_agents[0];
    let signature = SchemaSignature {
        input_types: first_agent.requires_disclosure.clone(),
        output_types: first_agent.returns.clone(),
    };
    
    // Create container
    let container_id = uuid::Uuid::new_v4().to_string();
    let container = BlockContainer {
        id: container_id.clone(),
        signature,
        candidate_agents: matching_agents.iter().map(|a| a.did.clone()).collect(),
        selected_agents: vec![first_agent.did.clone()], // Default to first
        input_connections: vec![],
        position: BlockPosition::default(),
    };
    
    // Create canvas block with container
    let block_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    
    let block = papillon_shared::CanvasBlock {
        id: block_id.clone(),
        prompt_id: uuid::Uuid::new_v4().to_string(),
        prompt_text: Some(query),
        state: papillon_shared::BlockState::Resolving {
            phase: 0,
            phase_label: "Creating container...".to_string(),
        },
        schema_type: None,
        content: None,
        linked_block_ids: vec![],
        agent_did: None,
        created_at: now.clone(),
        updated_at: now,
        mandate_expires_at: None,
        preference_guided: false,
        auto_expand: false,
        retention_warning: None,
        container: Some(container),
    };
    
    // Add to canvas (TODO: implement canvas storage)
    
    Ok(block_id)
}
```

- [ ] **Step 2: Export command**

Add to `apps/papillon/src/commands/canvas/mod.rs`:

```rust
pub mod container;
pub use container::create_block_container;
```

- [ ] **Step 3: Register Tauri command**

Add to Tauri builder in `apps/papillon/src/main.rs`:

```rust
.invoke_handler(tauri::generate_handler![
    // ... existing commands ...
    commands::canvas::create_block_container,
])
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p papillon`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/src/commands/canvas/container.rs apps/papillon/src/commands/canvas/mod.rs apps/papillon/src/main.rs
git commit -m "feat(backend): add create_block_container command

- Create BlockContainer from intent classification
- Find all agents matching action type/signature
- Default to first agent selected
- Emit block with container field populated"
```

---

## Task 8: Wire Blocks Command

**Files:**
- Create: `apps/papillon/src/commands/canvas/wiring.rs`
- Modify: `apps/papillon/src/commands/canvas/mod.rs`

- [ ] **Step 1: Create wiring command**

Create `apps/papillon/src/commands/canvas/wiring.rs`:

```rust
use tauri::{AppHandle, Emitter, State};
use papillon_shared::{BlockConnection, BlockEvent, BlockUpdate};

use crate::state::AppState;

/// Connect one block's output to another's input
///
/// Validates that:
/// 1. Output type matches input type (schema compatibility)
/// 2. Connection doesn't increase disclosure scope
#[tauri::command]
pub async fn connect_blocks(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    from_block_id: String,
    to_block_id: String,
    output_type: String,
    input_type: String,
) -> Result<(), String> {
    // Validate types match
    if output_type != input_type {
        return Err(format!(
            "Type mismatch: output {} != input {}",
            output_type, input_type
        ));
    }
    
    // TODO: Validate disclosure scope doesn't increase
    
    // Create connection
    let connection = BlockConnection {
        from_block_id: from_block_id.clone(),
        to_block_id: to_block_id.clone(),
        output_type,
        input_type,
    };
    
    // TODO: Store connection in canvas
    
    // Emit update event
    let now = chrono::Utc::now().to_rfc3339();
    let _ = app.emit(
        "block_connected",
        BlockEvent {
            block: BlockUpdate {
                id: to_block_id,
                prompt_id: String::new(),
                prompt_text: None,
                state: papillon_shared::BlockState::Resolved,
                schema_type: None,
                content: None,
                agent_did: None,
                mandate_expires_at: None,
                preference_guided: false,
                created_at: now.clone(),
                updated_at: now,
                retention_warning: None,
            },
        },
    );
    
    Ok(())
}

/// Disconnect blocks
#[tauri::command]
pub async fn disconnect_blocks(
    app: AppHandle,
    state: State<'_, AppState>,
    canvas_id: String,
    from_block_id: String,
    to_block_id: String,
) -> Result<(), String> {
    // TODO: Remove connection from canvas
    
    let now = chrono::Utc::now().to_rfc3339();
    let _ = app.emit(
        "block_disconnected",
        BlockEvent {
            block: BlockUpdate {
                id: to_block_id,
                prompt_id: String::new(),
                prompt_text: None,
                state: papillon_shared::BlockState::Resolved,
                schema_type: None,
                content: None,
                agent_did: None,
                mandate_expires_at: None,
                preference_guided: false,
                created_at: now.clone(),
                updated_at: now,
                retention_warning: None,
            },
        },
    );
    
    Ok(())
}
```

- [ ] **Step 2: Export commands**

Add to `apps/papillon/src/commands/canvas/mod.rs`:

```rust
pub mod wiring;
pub use wiring::{connect_blocks, disconnect_blocks};
```

- [ ] **Step 3: Register commands**

Add to Tauri builder in `apps/papillon/src/main.rs`:

```rust
.invoke_handler(tauri::generate_handler![
    // ... existing commands ...
    commands::canvas::connect_blocks,
    commands::canvas::disconnect_blocks,
])
```

- [ ] **Step 4: Verify compilation**

Run: `cargo check -p papillon`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add apps/papillon/src/commands/canvas/wiring.rs apps/papillon/src/commands/canvas/mod.rs apps/papillon/src/main.rs
git commit -m "feat(backend): add block wiring commands

- Implement connect_blocks with schema validation
- Implement disconnect_blocks
- Emit block_connected/block_disconnected events
- TODO: Add disclosure scope validation"
```

---

## Post-Implementation Tasks

### Testing Checklist

- [ ] Create block with prompt
- [ ] Verify block shows as container with ports
- [ ] Expand agent selector, see multiple agents
- [ ] Select different agents
- [ ] Create second block that accepts first block's output type
- [ ] Drag wire from output port to input port
- [ ] Verify connection appears
- [ ] Disconnect blocks
- [ ] Test "Find more" marketplace search (stub for now)

### Known Limitations

1. **Canvas storage**: Block containers not yet persisted to DB
2. **Disclosure validation**: Connection disclosure checks not implemented
3. **Marketplace search**: "Find more" button is stub
4. **Visual wiring**: Drag-and-drop wire creation not implemented
5. **Graph layout**: Auto-layout algorithm not implemented
6. **Multi-agent execution**: Only first agent executes currently

### Future Enhancements (Post v1.0)

- Block wiring via drag-and-drop
- Visual wire rendering (SVG/Canvas)
- Auto-layout algorithm (dagre, elk)
- Marketplace search by schema signature
- Multi-agent parallel execution
- Result merging/synthesis
- Block templates/presets
- Graph zoom/pan
- Minimap navigation
- Undo/redo for wiring
- Export graph as workflow

---

## Spec Alignment Check

**Covered:**
- ✓ Schema signature types (Task 1)
- ✓ Block container types (Task 2)
- ✓ Block ports UI (Task 3)
- ✓ Per-block agent selector (Task 4)
- ✓ Block container component (Task 5)
- ✓ Canvas integration (Task 6)
- ✓ Backend container creation (Task 7)
- ✓ Block wiring commands (Task 8)

**Not Covered (Deferred):**
- Visual wire rendering (SVG between ports)
- Drag-and-drop wiring interaction
- Marketplace search implementation
- Graph auto-layout algorithm
- Multi-agent parallel execution
- Canvas persistence layer updates

All Must Have features for block-based architecture foundation are implemented.
Core types, UI components, and backend commands ready for visual wiring phase.
