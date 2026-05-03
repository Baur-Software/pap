use leptos::prelude::*;
use papillon_shared::types::{CanvasMessageRecord, CanvasRecord};
use papillon_shared::{resolve_pap_uri, LinkOrigin, ResolvedUri};
use papillon_shared::{BlockState, BlockUpdate, Canvas, CanvasBlock};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::service::PapillonService;
use crate::state::catalog::CatalogState;
use crate::state::registry::RegistryState;
use crate::workflow_labels::workflow_port_label;

pub use papillon_shared::{filter_messages_by_canvas, merge_canvases_from_records, merge_messages_dedup};

/// Which face of the canvas flipper is visible.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CanvasSide {
    Front,
    Back,
}

/// Typed canvas lifecycle events emitted by [`CanvasState::apply_block_event`]
/// and note mutation methods. Components can subscribe to `last_event` instead
/// of the full `canvases` vec to react to specific event types without triggering
/// unnecessary re-renders from unrelated block updates.
#[derive(Clone, Debug, PartialEq)]
pub enum CanvasEvent {
    /// A block moved from one Resolving phase to the next.
    BlockPhaseChanged { block_id: String, phase: u8, phase_label: String },
    /// A block reached `BlockState::Resolved`.
    BlockResolved { block_id: String, schema_type: Option<String> },
    /// A block reached `BlockState::Failed`.
    BlockFailed { block_id: String, reason: String },
    /// A block became `BlockState::Outcome` (synthesized multi-agent result).
    BlockOutcome { block_id: String },
    /// A Guide block was upserted after 2+ blocks resolved.
    GuideRefreshed { canvas_id: String },
    /// A Note block was created, updated, or deleted.
    NoteChanged { block_id: String },
    /// A new non-guide block was inserted into a canvas.
    BlockCreated { block_id: String, canvas_id: String },
    /// A block was deleted from a canvas.
    BlockDeleted { block_id: String, canvas_id: String },
}

/// A pending Human-in-the-Loop gate request.
#[derive(Clone, Debug)]
pub struct HitlRequest {
    pub agent_name: String,
    pub action_type: String, // e.g. "schema:WriteAction"
    pub risk_level: String,  // "HIGH" or "CRITICAL"
    pub disclosure_props: Vec<String>,
    pub description: String,
}

/// Global canvas state — tracks canvases, blocks, and prompts.
#[derive(Clone, Copy)]
pub struct CanvasState {
    /// All saved canvases.
    pub canvases: RwSignal<Vec<Canvas>>,
    /// The currently active canvas ID.
    pub current_canvas_id: RwSignal<Option<String>>,
    /// If re-prompting an existing block, its ID.
    pub reshape_block_id: RwSignal<Option<String>>,
    /// Recent prompts for palette suggestions.
    pub recent_prompts: RwSignal<Vec<String>>,
    /// Bumped to signal the inline prompt should grab focus.
    pub focus_prompt: RwSignal<u32>,
    /// Set by agent tiles to prefill the prompt input.
    pub prefill_prompt: RwSignal<Option<String>>,
    /// Pending HitL gate — set by the protocol layer, cleared by user decision.
    pub hitl_pending: RwSignal<Option<HitlRequest>>,
    /// Tracks block IDs for which an approval invoke is in-flight (prevents double-submit).
    pub approval_in_flight: RwSignal<std::collections::HashSet<String>>,
    /// Which face of the canvas flip container is visible.
    pub canvas_side: RwSignal<CanvasSide>,
    /// Conversation messages for the active canvas chat thread.
    pub canvas_messages: RwSignal<Vec<CanvasMessageRecord>>,
    /// When set, the named block should expand itself and then clear this signal.
    pub requested_expansion: RwSignal<Option<String>>,
    /// Maps block_id → schema_type override for client-side template reshaping.
    /// Changing this causes the block renderer to use the override schema type
    /// for registry lookup without touching the persisted block content.
    pub block_template_overrides: RwSignal<std::collections::HashMap<String, String>>,
    /// The most recent typed event emitted by block lifecycle mutations.
    /// Components can subscribe to this instead of the full `canvases` vec
    /// to react to specific event types without unnecessary re-renders.
    pub last_event: RwSignal<Option<CanvasEvent>>,
    /// Live workflow graph for the active canvas, derived from block state.
    pub workflow_graph: RwSignal<papillon_shared::WorkflowGraph>,
}

impl Default for CanvasState {
    fn default() -> Self {
        Self {
            canvases: RwSignal::new(Vec::new()),
            current_canvas_id: RwSignal::new(None),
            reshape_block_id: RwSignal::new(None),
            recent_prompts: RwSignal::new(Vec::new()),
            focus_prompt: RwSignal::new(0),
            prefill_prompt: RwSignal::new(None),
            hitl_pending: RwSignal::new(None),
            approval_in_flight: RwSignal::new(std::collections::HashSet::new()),
            canvas_side: RwSignal::new(CanvasSide::Front),
            canvas_messages: RwSignal::new(Vec::new()),
            requested_expansion: RwSignal::new(None),
            block_template_overrides: RwSignal::new(std::collections::HashMap::new()),
            last_event: RwSignal::new(None),
            workflow_graph: RwSignal::new(papillon_shared::WorkflowGraph::default()),
        }
    }
}

/// Derive a `WorkflowGraph` from a slice of canvas blocks.
///
/// Nodes follow real block lifecycle state so the workflow surface can translate
/// PAP internals into human decisions without inventing fake authoring state.
/// Edges come from explicit `{{block:<id>}}` references plus persisted block links.
pub fn derive_map_graph(blocks: &[CanvasBlock]) -> papillon_shared::WorkflowGraph {
    use papillon_shared::{
        types::PipelineNodeType, EdgeState, PortRef, WorkflowEdge, WorkflowGraph, WorkflowNode,
    };

    let nodes: Vec<WorkflowNode> = blocks
        .iter()
        .enumerate()
        .filter(|(_, block)| !matches!(block.state, papillon_shared::BlockState::Guide { .. }))
        .map(|(i, b)| {
            // Use agent_name extracted from Ghost/AwaitingApproval state, or fall back
            // to schema_type, or truncated prompt text.
            let (node_type, agent_name, action_type, input_ports, output_ports) = match &b.state {
                papillon_shared::BlockState::Ghost {
                    agent_name,
                    action_type,
                    disclosure_preview,
                    returns_preview,
                    ..
                } => (
                    PipelineNodeType::Agent,
                    Some(agent_name.clone()),
                    action_type.clone(),
                    build_workflow_ports(disclosure_preview, true),
                    build_workflow_ports(returns_preview, false),
                ),
                papillon_shared::BlockState::AwaitingApproval { plan } => (
                    PipelineNodeType::Agent,
                    Some(plan.selected_agent_name.clone()),
                    plan.action.clone(),
                    build_workflow_ports(&plan.requires_disclosure, true),
                    build_workflow_ports(&plan.returns, false),
                ),
                papillon_shared::BlockState::Outcome { .. } => (
                    PipelineNodeType::Synthesizer,
                    Some("Papillon".into()),
                    "schema:SynthesizeAction".into(),
                    Vec::new(),
                    block_schema_ports(b),
                ),
                papillon_shared::BlockState::Note { .. } => (
                    PipelineNodeType::Agent,
                    Some("Note".into()),
                    "note".into(),
                    Vec::new(),
                    vec![PortRef {
                        path: "note".into(),
                        label: "Note".into(),
                        required: false,
                    }],
                ),
                _ => (
                    PipelineNodeType::Agent,
                    None,
                    String::new(),
                    Vec::new(),
                    block_schema_ports(b),
                ),
            };
            WorkflowNode {
                id: b.id.clone(),
                node_type,
                intent: b.prompt_text.clone().unwrap_or_default(),
                agent_name,
                agent_did: b.agent_did.clone(),
                pap_uri: b.agent_did.as_ref().map(|did| format!("pap://{did}")),
                action_type,
                input_ports,
                output_ports,
                template_override: None,
                position_x: (i as f64) * 320.0,
                position_y: 0.0,
            }
        })
        .collect();

    let mut edges: Vec<WorkflowEdge> = Vec::new();
    let mut edge_counter: u32 = 0;
    let mut seen_relationships = std::collections::BTreeSet::<(String, String)>::new();

    for block in blocks {
        // Extract {{block:ID}} refs from prompt text
        let prompt = block.prompt_text.as_deref().unwrap_or("");
        let mut remaining = prompt;
        while let Some(start) = remaining.find("{{block:") {
            remaining = &remaining[start + 8..];
            if let Some(end) = remaining.find("}}") {
                let ref_id = &remaining[..end];
                let edge_key = (ref_id.to_string(), block.id.clone());
                if !ref_id.is_empty()
                    && blocks.iter().any(|b| b.id == ref_id)
                    && seen_relationships.insert(edge_key)
                {
                    edge_counter += 1;
                    edges.push(WorkflowEdge {
                        id: format!("map-edge-{edge_counter}"),
                        from_node_id: ref_id.to_string(),
                        from_port: PortRef {
                            path: "result".into(),
                            label: "Result".into(),
                            required: false,
                        },
                        to_node_id: block.id.clone(),
                        to_port: PortRef {
                            path: "context".into(),
                            label: "Context".into(),
                            required: false,
                        },
                        state: EdgeState::Confirmed,
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
            let edge_key = (linked_id.clone(), block.id.clone());
            if blocks.iter().any(|b| &b.id == linked_id) && seen_relationships.insert(edge_key) {
                edge_counter += 1;
                edges.push(WorkflowEdge {
                    id: format!("map-linked-{edge_counter}"),
                    from_node_id: linked_id.clone(),
                    from_port: PortRef {
                        path: "linked_result".into(),
                        label: "Linked result".into(),
                        required: false,
                    },
                    to_node_id: block.id.clone(),
                    to_port: PortRef {
                        path: "linked_context".into(),
                        label: "Linked context".into(),
                        required: false,
                    },
                    state: EdgeState::Confirmed,
                    memex_remembered: false,
                });
            }
        }
    }

    WorkflowGraph {
        nodes,
        edges,
        is_designed: false,
    }
}

fn build_workflow_ports(paths: &[String], required: bool) -> Vec<papillon_shared::PortRef> {
    paths
        .iter()
        .map(|path| papillon_shared::PortRef {
            path: path.clone(),
            label: workflow_port_label(path),
            required,
        })
        .collect()
}

fn block_schema_ports(block: &CanvasBlock) -> Vec<papillon_shared::PortRef> {
    block
        .schema_type
        .as_ref()
        .map(|schema_type| {
            vec![papillon_shared::PortRef {
                path: schema_type.clone(),
                label: workflow_port_label(schema_type),
                required: false,
            }]
        })
        .unwrap_or_default()
}

/// Extract block IDs from `{{block:ID}}` patterns in prompt text.
fn extract_block_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut search = text;
    while let Some(start) = search.find("{{block:") {
        let after = &search[start + 8..];
        if let Some(end) = after.find("}}") {
            let id = &after[..end];
            if !id.is_empty() {
                ids.push(id.to_string());
            }
            search = &after[end + 2..];
        } else {
            break;
        }
    }
    ids
}

/// Expand `{{block:BLOCK_ID}}` references in prompt text.
/// Replaces each reference with the JSON content of the referenced block's result.
fn expand_block_references(text: &str, canvases: &[Canvas]) -> String {
    let mut result = text.to_string();
    // Iteratively find and replace {{block:...}} patterns
    // Use a safety limit to prevent infinite loops on malformed input
    for _ in 0..50 {
        if let Some(start) = result.find("{{block:") {
            if let Some(rel_end) = result[start..].find("}}") {
                let end = start + rel_end;
                let full_match = result[start..end + 2].to_string();
                let block_id = &result[start + 8..end];
                let replacement = canvases
                    .iter()
                    .flat_map(|c| c.blocks.iter())
                    .find(|b| b.id == block_id)
                    .and_then(|b| b.content.as_ref())
                    .map(|c| c.get("result").unwrap_or(c).to_string())
                    .unwrap_or_else(|| format!("[block {} not found]", block_id));
                result = result.replace(&full_match, &replacement);
            } else {
                break; // Malformed reference
            }
        } else {
            break; // No more references
        }
    }
    result
}

/// If `text` is a `pap://` URI, resolve it using the local catalog and return
/// the [`ResolvedUri`] variant so callers can pattern-match on the resolution
/// type (e.g. to detect `HttpsEndpoint` for browse-mode blocks).
///
/// Non-`pap://` text is wrapped in [`ResolvedUri::LocalIntent`] and passed
/// through unchanged — the backend interprets it as natural language or a bare
/// URL.
///
/// Returns `None` (and logs a warning) only when URI resolution genuinely fails.
fn resolve_prompt_text(text: &str, origin: LinkOrigin) -> Option<ResolvedUri> {
    let is_pap = text.starts_with("pap://")
        || text.starts_with("pap+https://")
        || text.starts_with("pap+wss://");

    if !is_pap {
        return Some(ResolvedUri::LocalIntent(text.to_string()));
    }

    let catalog_map = use_context::<CatalogState>()
        .map(|c| c.snapshot())
        .unwrap_or_default();

    match resolve_pap_uri(text, &catalog_map, origin) {
        Ok(resolved) => Some(resolved),
        Err(e) => {
            leptos::logging::warn!("PAP URI resolution failed for {}: {:?}", text, e);
            None
        }
    }
}

/// Extract the inner `String` from any [`ResolvedUri`] variant.
fn resolved_uri_text(r: &ResolvedUri) -> &str {
    match r {
        ResolvedUri::LocalIntent(s)
        | ResolvedUri::Did(s)
        | ResolvedUri::Registry(s)
        | ResolvedUri::HttpsEndpoint(s)
        | ResolvedUri::WssEndpoint(s) => s.as_str(),
    }
}

impl CanvasState {
    /// Create a new blank canvas, set it active, and signal the prompt to focus.
    pub fn new_canvas(&self) -> String {
        let id = generate_id();
        let now = now_iso();
        let canvas = Canvas {
            id: id.clone(),
            name: "Untitled canvas".into(),
            blocks: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        };
        self.canvases.update(|c| c.push(canvas));
        self.current_canvas_id.set(Some(id.clone()));
        self.focus_prompt.update(|n| *n += 1);
        id
    }

    /// Rename the active canvas in-place and persist it when Tauri is available.
    pub fn rename_current_canvas(&self, next_name: String) {
        let canvas_id = match self.current_canvas_id.get_untracked() {
            Some(id) => id,
            None => return,
        };
        let Some(next_name) = normalize_canvas_name(&next_name) else {
            return;
        };

        let mut renamed = false;
        self.canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                if canvas.name == next_name {
                    return;
                }
                canvas.name = next_name.clone();
                canvas.updated_at = now_iso();
                renamed = true;
            }
        });

        if !renamed || !crate::bridge::tauri_available() {
            return;
        }

        spawn_local(async move {
            #[derive(serde::Serialize)]
            struct RenameArgs {
                id: String,
                name: String,
            }

            if let Err(e) = crate::bridge::invoke::<_, serde_json::Value>(
                "canvas_rename",
                &RenameArgs {
                    id: canvas_id,
                    name: next_name,
                },
            )
            .await
            {
                leptos::logging::warn!("canvas_rename failed: {}", e);
            }
        });
    }

    /// Programmatically request that a specific block expand itself.
    /// Flips to the Front face so the block is visible, then signals it.
    pub fn expand_block(&self, block_id: String) {
        self.canvas_side.set(CanvasSide::Front);
        self.requested_expansion.set(Some(block_id));
    }

    /// Append a `{{block:ID}}` reference to the current topbar prefill prompt.
    /// Bumps `focus_prompt` so the address bar grabs focus for the user to complete
    /// and submit the composed query.
    pub fn insert_block_ref(&self, block_id: String) {
        let current = self.prefill_prompt.get_untracked().unwrap_or_default();
        self.prefill_prompt
            .set(Some(format!("{}{{{{block:{}}}}}", current, block_id)));
        self.focus_prompt.update(|n| *n += 1);
    }

    /// Apply a template override to an existing resolved block.
    /// This changes how the block's content is rendered without re-executing the
    /// agent. The override is stored in `block_template_overrides` and takes
    /// priority over the block's persisted `schema_type` during renderer lookup.
    pub fn reshape_block_template(&self, block_id: String, schema_type_override: String) {
        self.block_template_overrides.update(|map| {
            map.insert(block_id, schema_type_override);
        });
    }

    /// Create a new user-authored note block on the current canvas.
    pub fn create_note(&self, title: String, content: String) {
        let canvas_id = match self.current_canvas_id.get_untracked() {
            Some(id) => id,
            None => return,
        };
        let canvases = self.canvases;
        let self_signal = *self;
        spawn_local(async move {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct NoteArgs { canvas_id: String, title: String, content: String }
            match crate::bridge::invoke::<_, CanvasBlock>(
                "canvas_create_note",
                &NoteArgs { canvas_id: canvas_id.clone(), title, content },
            ).await {
                Ok(block) => {
                    let block_id = block.id.clone();
                    canvases.update(|cs| {
                        if let Some(c) = cs.iter_mut().find(|c| c.id == canvas_id) {
                            c.blocks.push(block);
                        }
                    });
                    self_signal.last_event.set(Some(CanvasEvent::NoteChanged {
                        block_id,
                    }));
                }
                Err(e) => leptos::logging::error!("create_note: {:?}", e),
            }
        });
    }

    /// Seed the first-ever canvas with live agent queries so the app
    /// opens with real content resolving through the handshake pipeline.
    ///
    /// All current catalog agents declare `requires_disclosure = []` (zero-disclosure).
    /// The PAP approval gate auto-approves these without a manual gate and each
    /// resolved block shows the `zero disclosure · no data left this device` badge,
    /// demonstrating the privacy model on first launch.
    ///
    /// When a catalog agent with non-empty `requires_disclosure` is added, the third
    /// seed prompt should be replaced with a prompt that targets it — ensuring every
    /// new user consciously approves at least one disclosure-gated agent on first launch.
    pub fn seed_first_canvas(&self) {
        const SEED_PROMPTS: &[&str] = &[
            "hacker news",
            "define protocol",
            // Zero-disclosure demo: on-device lookup, no data leaves the device.
            // Replace with a disclosure-requiring prompt once such an agent ships in catalog.
            "what is the principal agent protocol",
        ];

        let canvas_id = self.new_canvas();
        self.canvases.update(|cs| {
            if let Some(c) = cs.iter_mut().find(|c| c.id == canvas_id) {
                c.name = "Welcome".into();
            }
        });

        for prompt in SEED_PROMPTS {
            self.submit_prompt(prompt.to_string());
        }
    }

    /// Remove a block from the current canvas by ID.
    pub fn delete_block(&self, block_id: &str) {
        let block_id = block_id.to_string();
        let canvas_id = match self.current_canvas_id.get_untracked() {
            Some(id) => id,
            None => return,
        };
        self.canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                canvas.blocks.retain(|b| b.id != block_id);
                canvas.updated_at = now_iso();
            }
        });
    }

    /// Delete a canvas by ID. If it was the active canvas, select the previous one.
    pub fn delete_canvas(&self, id: &str) {
        let id = id.to_string();
        self.canvases.update(|cs| cs.retain(|c| c.id != id));
        // If the deleted canvas was active, switch to the last remaining one
        if self.current_canvas_id.get_untracked().as_deref() == Some(&id) {
            let next = self.canvases.get_untracked().last().map(|c| c.id.clone());
            self.current_canvas_id.set(next);
        }
    }

    /// Get the currently active canvas, if any.
    pub fn current_canvas(&self) -> Option<Canvas> {
        let id = self.current_canvas_id.get()?;
        self.canvases.get().into_iter().find(|c| c.id == id)
    }

    /// Returns a `Memo` that yields the block list for the currently active canvas.
    /// Only re-fires when the active canvas's blocks change — not when other canvases
    /// change or when `current_canvas_id` itself switches (structural vs. content change).
    ///
    /// Use in place of the `move || canvas_state.current_canvas().map(|c| c.blocks)`
    /// closure pattern so that only actual block mutations cause downstream re-runs.
    pub fn current_canvas_blocks(&self) -> Memo<Vec<CanvasBlock>> {
        let canvases = self.canvases;
        let current_id = self.current_canvas_id;
        Memo::new(move |_| {
            let id = current_id.get();
            canvases
                .get()
                .into_iter()
                .find(|c| Some(c.id.clone()) == id)
                .map(|c| c.blocks)
                .unwrap_or_default()
        })
    }

    /// Returns a `Memo` that yields `Some(CanvasBlock)` for the given block ID
    /// whenever that block's data changes, or `None` if the block no longer exists.
    ///
    /// Leptos's `Memo` compares the previous and new values via `PartialEq` before
    /// notifying subscribers — so if an unrelated block changes but *this* block's
    /// data is unchanged, no re-render is triggered for the subscriber.
    ///
    /// Use in `BlockRenderer` so that only updates to *this* block's `updated_at`
    /// (or any other field) cause its subtree to re-evaluate.
    pub fn block_signal(&self, block_id: String) -> Memo<Option<CanvasBlock>> {
        let canvases = self.canvases;
        Memo::new(move |_| {
            canvases
                .get()
                .into_iter()
                .flat_map(|c| c.blocks.into_iter())
                .find(|b| b.id == block_id)
        })
    }

    /// Submit a new prompt — creates blocks via the backend.
    pub fn submit_prompt(&self, text: String) {
        let recent = self.recent_prompts;
        recent.update(|r| {
            r.retain(|p| p != &text);
            r.insert(0, text.clone());
            r.truncate(10);
        });

        let resolved_uri = match resolve_prompt_text(&text, LinkOrigin::Principal) {
            Some(r) => r,
            None => return,
        };
        self.dispatch_prompt_inner(text, resolved_uri, None);
    }

    /// Dispatch a pap:// link that originated from an agent-rendered block.
    /// Resolves under `LinkOrigin::Agent` so special authorities
    /// (receipt, canvas, settings) are blocked.
    ///
    /// `source_block_id` is the block that contained the link — the new block
    /// is added to its `linked_block_ids` to preserve the JSON-LD navigation
    /// graph across the browsing session.
    pub fn submit_agent_link(&self, url: String, source_block_id: Option<String>) {
        if let Some(resolved_uri) = resolve_prompt_text(&url, LinkOrigin::Agent) {
            self.dispatch_prompt_inner(url, resolved_uri, source_block_id);
        }
        // On None: error already logged by resolve_prompt_text
    }

    /// Core dispatch: creates an optimistic block, then fires the backend
    /// command with the pre-resolved text.  Never runs the URI resolver —
    /// callers are responsible for resolving under the correct `LinkOrigin`
    /// before calling this method.
    ///
    /// `resolved_uri` carries the resolution type — `HttpsEndpoint` sets
    /// `auto_expand = true` on the new block (browse mode).
    /// `source_block_id` links the new block to the block that spawned it.
    fn dispatch_prompt_inner(
        &self,
        display_text: String,
        resolved_uri: ResolvedUri,
        source_block_id: Option<String>,
    ) {
        let canvases = self.canvases;
        let current_id = self.current_canvas_id;

        let prompt_id = generate_id();

        // Auto-rename untitled canvases from the first prompt
        if let Some(id) = current_id.get() {
            canvases.update(|cs| {
                if let Some(c) = cs.iter_mut().find(|c| c.id == id) {
                    if c.name == "Untitled canvas" && c.blocks.is_empty() {
                        c.name = auto_name_from_prompt(&display_text);
                    }
                }
            });
        }

        let canvas_id = current_id.get().unwrap_or_else(|| {
            // Create a new canvas auto-named from the prompt
            let new_id = generate_id();
            let name = auto_name_from_prompt(&display_text);
            let now = now_iso();
            let canvas = Canvas {
                id: new_id.clone(),
                name,
                blocks: Vec::new(),
                created_at: now.clone(),
                updated_at: now,
            };
            canvases.update(|c| c.push(canvas));
            current_id.set(Some(new_id.clone()));
            new_id
        });

        // `auto_expand` is true for browse URLs (HttpsEndpoint) — fills the viewport.
        let auto_expand = matches!(resolved_uri, ResolvedUri::HttpsEndpoint(_));
        // Extract the resolved string for the backend handshake.
        let resolved_text = resolved_uri_text(&resolved_uri).to_string();

        // Extract block references from the display text, then merge in the
        // source block (the block whose link spawned this one).
        let mut linked_block_ids = extract_block_ids(&display_text);
        if let Some(src) = source_block_id {
            if !linked_block_ids.contains(&src) {
                linked_block_ids.push(src);
            }
        }

        // Save a copy of the display text for persistence before it is moved.
        let display_text_for_persist = display_text.clone();

        // Create a resolving block immediately (optimistic UI)
        let block = CanvasBlock {
            id: generate_id(),
            prompt_id: prompt_id.clone(),
            prompt_text: Some(display_text),
            state: BlockState::Resolving {
                phase: 1,
                phase_label: "Discovering agents...".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids,
            agent_did: None,
            mandate_expires_at: None,
            preference_guided: false,
            auto_expand,
            retention_warning: None,
            created_at: now_iso(),
            updated_at: now_iso(),
        };

        let block_id = block.id.clone();

        canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                canvas.blocks.push(block);
                canvas.updated_at = now_iso();
            }
        });

        // Expand block references in the resolved text for the backend
        let all_canvases = canvases.get();
        let expanded_text = expand_block_references(&resolved_text, &all_canvases);

        // Fire backend command with expanded text
        let cid = canvas_id.clone();

        // Persist the new block to the DB. Log errors but don't block the handshake.
        {
            let block_id_db = block_id.clone();
            let canvas_id_db = canvas_id.clone();
            let prompt_db = display_text_for_persist.clone();
            let display_order = canvases.get_untracked()
                .iter()
                .find(|c| c.id == canvas_id_db)
                .map(|c| c.blocks.len() as i64)
                .unwrap_or(0);
            spawn_local(async move {
                if crate::bridge::tauri_available() {
                    match crate::bridge::invoke::<_, serde_json::Value>(
                        "canvas_block_create",
                        &serde_json::json!({
                            "canvasId": canvas_id_db,
                            "blockId": block_id_db,
                            "promptText": prompt_db,
                            "displayOrder": display_order,
                        }),
                    ).await {
                        Ok(_) => {
                            leptos::logging::debug!("Block {} persisted to DB", block_id_db);
                        }
                        Err(e) => {
                            leptos::logging::error!(
                                "Failed to persist block {} to DB: {}. Block will remain in memory only.",
                                block_id_db, e
                            );
                        }
                    }
                }
            });
        }
        // Add user message to the chat thread.
        {
            let canvas_messages = self.canvas_messages;
            let canvas_id_msg = canvas_id.clone();
            let display_text_msg = display_text_for_persist.clone();
            let block_id_msg = block_id.clone();
            let msg_id = generate_id();
            let now = now_iso();
            let record = CanvasMessageRecord {
                id: msg_id,
                canvas_id: canvas_id_msg.clone(),
                role: "user".to_string(),
                content: display_text_msg.clone(),
                block_id: Some(block_id_msg.clone()),
                created_at: now,
            };
            canvas_messages.update(|ms| ms.push(record));
            spawn_local(async move {
                if crate::bridge::tauri_available() {
                    if let Err(e) = crate::bridge::invoke::<_, serde_json::Value>(
                        "canvas_message_add",
                        &serde_json::json!({
                            "canvasId": canvas_id_msg,
                            "role": "user",
                            "content": display_text_msg,
                            "blockId": block_id_msg,
                        }),
                    ).await {
                        leptos::logging::warn!("Failed to persist message to DB: {}. Message will remain in memory only.", e);
                    }
                }
            });
        }

        // Capture Leptos contexts now (in the component scope) — spawn_local
        // runs outside reactive ownership so expect_context would panic there.
        let service = use_context::<std::sync::Arc<dyn PapillonService>>();
        let registry = use_context::<RegistryState>();

        spawn_local(async move {
            let result = if bridge::tauri_available() {
                // Tauri IPC path — delegates to native backend handshake
                #[derive(serde::Serialize)]
                #[serde(rename_all = "camelCase")]
                struct CanvasPromptArgs {
                    canvas_id: String,
                    prompt_id: String,
                    block_id: String,
                    text: String,
                }
                let args = CanvasPromptArgs {
                    canvas_id: cid,
                    prompt_id,
                    block_id: block_id.clone(),
                    text: expanded_text,
                };
                bridge::invoke::<_, serde_json::Value>("canvas_plan_prompt", &args)
                    .await
                    .map(|_| ())
            } else {
                // WASM-native handshake — runs the 6-phase protocol directly
                // in the browser via fetch(), bypassing Tauri IPC entirely.
                match (service, registry) {
                    (Some(svc), Some(reg)) => {
                        crate::handshake::run_prompt(
                            canvases,
                            canvas_id.clone(),
                            block_id.clone(),
                            expanded_text,
                            svc,
                            reg,
                        )
                        .await
                    }
                    _ => Err("Service or registry context not available".to_string()),
                }
            };

            if let Err(e) = result {
                // Mark block as failed — but only if the on_fail callback hasn't
                // already set it (the callback knows the correct phase number).
                canvases.update(|cs| {
                    if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                        if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
                            if !matches!(b.state, BlockState::Failed { .. }) {
                                b.state = BlockState::Failed {
                                    phase: 1,
                                    reason: e,
                                };
                                b.updated_at = now_iso();
                            }
                        }
                    }
                });
            }
        });
    }

    /// Submit a reshape prompt for an existing block.
    pub fn submit_reshape(&self, block_id: String, text: String) {
        self.reshape_block_id.set(None);

        let canvases = self.canvases;
        let current_id = self.current_canvas_id;
        let canvas_id = match current_id.get() {
            Some(id) => id,
            None => return,
        };

        // Mark the block as resolving again
        canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
                    b.state = BlockState::Resolving {
                        phase: 1,
                        phase_label: "Reshaping...".into(),
                    };
                    b.updated_at = now_iso();
                }
            }
        });

        let bid = block_id.clone();
        let cid = canvas_id.clone();
        spawn_local(async move {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct ReshapeArgs {
                canvas_id: String,
                block_id: String,
                text: String,
            }
            let args = ReshapeArgs {
                canvas_id: cid.clone(),
                block_id: bid.clone(),
                text,
            };
            let result = bridge::invoke::<_, serde_json::Value>("canvas_reshape", &args).await;
            if let Err(e) = result {
                canvases.update(|cs| {
                    if let Some(canvas) = cs.iter_mut().find(|c| c.id == cid) {
                        if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == bid) {
                            b.state = BlockState::Failed {
                                phase: 1,
                                reason: e,
                            };
                            b.updated_at = now_iso();
                        }
                    }
                });
            }
        });
    }

    /// Retry a failed block by re-issuing the mandate with the original prompt text.
    pub fn retry_block(&self, block_id: String) {
        let canvases = self.canvases;
        let current_id = self.current_canvas_id;
        let canvas_id = match current_id.get() {
            Some(id) => id,
            None => return,
        };

        // Look up the original prompt text from the block
        let raw_text = canvases
            .get()
            .iter()
            .flat_map(|c| c.blocks.iter())
            .find(|b| b.id == block_id)
            .and_then(|b| b.prompt_text.clone())
            .unwrap_or_default();

        // Resolve pap:// URIs on retry too; extract inner string for backend.
        let original_text = match resolve_prompt_text(&raw_text, LinkOrigin::Principal) {
            Some(r) => resolved_uri_text(&r).to_string(),
            None => {
                canvases.update(|cs| {
                    if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                        if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
                            b.state = BlockState::Failed {
                                phase: 1,
                                reason: "PAP URI resolution failed — see console for details."
                                    .into(),
                            };
                            b.updated_at = now_iso();
                        }
                    }
                });
                return;
            }
        };

        canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
                    b.state = BlockState::Resolving {
                        phase: 1,
                        phase_label: "Retrying...".into(),
                    };
                    b.updated_at = now_iso();
                }
            }
        });

        let bid = block_id.clone();
        let cid = canvas_id.clone();
        spawn_local(async move {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct RetryArgs {
                canvas_id: String,
                block_id: String,
                original_text: String,
            }
            let args = RetryArgs {
                canvas_id: cid.clone(),
                block_id: bid.clone(),
                original_text, // now resolved
            };
            let result = bridge::invoke::<_, serde_json::Value>("canvas_retry", &args).await;
            if let Err(e) = result {
                canvases.update(|cs| {
                    if let Some(canvas) = cs.iter_mut().find(|c| c.id == cid) {
                        if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == bid) {
                            b.state = BlockState::Failed {
                                phase: 1,
                                reason: e,
                            };
                            b.updated_at = now_iso();
                        }
                    }
                });
            }
        });
    }

    /// Update a block from a Tauri event (called by event listener).
    pub fn update_block(&self, canvas_id: &str, updated_block: CanvasBlock) {
        self.canvases.update(|cs| {
            if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == updated_block.id) {
                    *b = updated_block;
                }
                canvas.updated_at = now_iso();
            }
        });
    }

    /// Approve an AwaitingApproval block — sends the decision to the backend
    /// and begins the handshake. Guards against double-submit via approval_in_flight.
    pub fn approve_block(&self, block_id: String, approval_request_id: String) {
        // Prevent double-submit
        if self.approval_in_flight.get_untracked().contains(&block_id) {
            leptos::logging::warn!(
                "Approval already in flight for block {}, ignoring duplicate request",
                block_id
            );
            return;
        }
        self.approval_in_flight.update(|s| {
            s.insert(block_id.clone());
        });

        let in_flight = self.approval_in_flight;
        let canvases = self.canvases;
        let block_id_clone = block_id.clone();

        spawn_local(async move {
            match crate::bridge::invoke::<_, serde_json::Value>(
                "canvas_approve_block",
                &serde_json::json!({
                    "approvalRequestId": approval_request_id,
                    "approved": true,
                }),
            )
            .await
            {
                Ok(_) => {
                    // Success - backend will send BlockUpdate event to transition state
                }
                Err(e) => {
                    leptos::logging::error!("approve_block failed for {}: {}", block_id_clone, e);
                    // Transition block to Failed state with the error message
                    canvases.update(|cs| {
                        for canvas in cs.iter_mut() {
                            if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id_clone) {
                                b.state = BlockState::Failed {
                                    phase: 2,
                                    reason: format!("Approval failed: {}", e),
                                };
                                b.updated_at = now_iso();
                                break;
                            }
                        }
                    });
                }
            }
            // Always remove from in-flight set to allow retry
            in_flight.update(|s| {
                s.remove(&block_id_clone);
            });
        });
    }

    /// Reject an AwaitingApproval block — sends the decision to the backend.
    pub fn reject_block(&self, block_id: String, approval_request_id: String) {
        let canvases = self.canvases;
        let block_id_clone = block_id.clone();
        spawn_local(async move {
            match crate::bridge::invoke::<_, serde_json::Value>(
                "canvas_approve_block",
                &serde_json::json!({
                    "approvalRequestId": approval_request_id,
                    "approved": false,
                }),
            )
            .await
            {
                Ok(_) => {
                    // Success - backend will send BlockUpdate event to transition state
                }
                Err(e) => {
                    leptos::logging::error!("reject_block failed for {}: {}", block_id_clone, e);
                    // On rejection failure, transition to Failed state
                    canvases.update(|cs| {
                        for canvas in cs.iter_mut() {
                            if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id_clone) {
                                b.state = BlockState::Failed {
                                    phase: 2,
                                    reason: format!("Rejection failed: {}", e),
                                };
                                b.updated_at = now_iso();
                                break;
                            }
                        }
                    });
                }
            }
        });
    }

    /// Apply a streaming phase update from the backend.
    /// Searches all canvases for the block by ID and directly assigns
    /// backend-owned fields. Frontend-only fields (`linked_block_ids`,
    /// `auto_expand`) are structurally absent from `BlockUpdate` and
    /// are therefore never touched — no save/restore needed.
    ///
    /// When the block transitions to Resolved or Failed, calls the
    /// corresponding Tauri persistence command (canvas_block_resolve /
    /// canvas_block_fail) via spawn_local — fire-and-forget, errors logged.
    ///
    /// When a canvas reaches 2+ resolved blocks, triggers `canvas_generate_guide`
    /// and upserts the Guide block at position 0.
    pub fn apply_block_event(&self, update: BlockUpdate) {
        let current_id = self.current_canvas_id;
        let canvases = self.canvases;
        let mut guide_canvas_id: Option<String> = None;

        self.canvases.update(|cs| {
            for canvas in cs.iter_mut() {
                if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == update.id) {
                    // Apply backend-owned fields directly.
                    b.prompt_id = update.prompt_id.clone();
                    b.state = update.state.clone();
                    b.schema_type = update.schema_type.clone();
                    b.content = update.content.clone();
                    b.agent_did = update.agent_did.clone();
                    b.mandate_expires_at = update.mandate_expires_at.clone();
                    b.preference_guided = update.preference_guided;
                    b.created_at = update.created_at.clone();
                    b.updated_at = update.updated_at.clone();
                    // Propagate retention warning when present; clear when absent
                    // (a retry that succeeds with TEE should clear a prior warning).
                    b.retention_warning = update.retention_warning.clone();
                    // Only overwrite prompt_text when the event carries one.
                    if let Some(pt) = update.prompt_text.clone() {
                        b.prompt_text = Some(pt);
                    }
                    canvas.updated_at = now_iso();

                    // Persist resolved/failed state to DB (Tauri path only).
                    let block_id = b.id.clone();
                    let canvas_id = canvas.id.clone();
                    match &update.state {
                        BlockState::Resolved => {
                            let schema_type = update.schema_type.clone().unwrap_or_default();
                            let content_json = update.content.as_ref()
                                .map(|c| c.to_string())
                                .unwrap_or_default();
                            let episode_id: Option<String> = update.content.as_ref()
                                .and_then(|c| c.get("episode_id"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            let agent_did = update.agent_did.clone();
                            let mandate_expires_at = update.mandate_expires_at.clone();
                            spawn_local(async move {
                                if crate::bridge::tauri_available() {
                                    let _ = crate::bridge::invoke::<_, serde_json::Value>(
                                        "canvas_block_resolve",
                                        &serde_json::json!({
                                            "blockId": block_id,
                                            "schemaType": schema_type,
                                            "contentJson": content_json,
                                            "episodeId": episode_id,
                                            "agentDid": agent_did,
                                            "mandateExpiresAt": mandate_expires_at,
                                        }),
                                    ).await;
                                    let _ = canvas_id; // used by closure
                                }
                            });
                        }
                        BlockState::Failed { reason, .. } => {
                            let reason = reason.clone();
                            spawn_local(async move {
                                if crate::bridge::tauri_available() {
                                    let _ = crate::bridge::invoke::<_, serde_json::Value>(
                                        "canvas_block_fail",
                                        &serde_json::json!({
                                            "blockId": block_id,
                                            "reason": reason,
                                        }),
                                    ).await;
                                    let _ = canvas_id;
                                }
                            });
                        }
                        _ => {}
                    }

                    // After a block resolves, check whether we should trigger a Guide refresh.
                    // Guard: only trigger when the new state is Resolved or Outcome.
                    if matches!(&update.state, BlockState::Resolved | BlockState::Outcome { .. }) {
                        // Count resolved blocks on this canvas, excluding Guide blocks.
                        let resolved_count = canvas.blocks.iter()
                            .filter(|b| {
                                !b.id.starts_with("guide-")
                                    && matches!(b.state, BlockState::Resolved | BlockState::Outcome { .. })
                            })
                            .count();
                        if resolved_count >= 2 {
                            guide_canvas_id = Some(canvas.id.clone());
                        }
                    }

                    return;
                }
            }
        });
        let _ = current_id;

        // Emit a typed event so fine-grained subscribers can react without reading
        // the full canvases vec. Uses `PartialEq` on `CanvasEvent` — if the same
        // event fires twice in a row (e.g. phase 2 → phase 2 on retry), the memo
        // won't re-notify but that is the correct behaviour (no change occurred).
        let typed_event = match &update.state {
            BlockState::Resolving { phase, phase_label } => Some(CanvasEvent::BlockPhaseChanged {
                block_id: update.id.clone(),
                phase: *phase,
                phase_label: phase_label.clone(),
            }),
            BlockState::Resolved => Some(CanvasEvent::BlockResolved {
                block_id: update.id.clone(),
                schema_type: update.schema_type.clone(),
            }),
            BlockState::Failed { reason, .. } => Some(CanvasEvent::BlockFailed {
                block_id: update.id.clone(),
                reason: reason.clone(),
            }),
            BlockState::Outcome { .. } => Some(CanvasEvent::BlockOutcome {
                block_id: update.id.clone(),
            }),
            _ => None,
        };
        if let Some(evt) = typed_event {
            self.last_event.set(Some(evt));
        }

        // Trigger guide generation outside the borrow of canvases.
        if let Some(cid) = guide_canvas_id {
            let guide_id = format!("guide-{}", cid);
            let cid_clone = cid.clone();

            // Collect summaries from resolved blocks (excluding guide blocks themselves).
            #[derive(serde::Serialize)]
            struct GuideSummaryPayload {
                schema_type: String,
                agent_name: String,
                snippet: String,
            }

            let summaries: Vec<GuideSummaryPayload> = canvases
                .get_untracked()
                .iter()
                .find(|c| c.id == cid)
                .map(|c| {
                    c.blocks.iter()
                        .filter(|b| {
                            !b.id.starts_with("guide-")
                                && matches!(b.state, BlockState::Resolved | BlockState::Outcome { .. })
                        })
                        .map(|b| GuideSummaryPayload {
                            schema_type: b.schema_type.clone().unwrap_or_default(),
                            agent_name: b.agent_did.as_deref()
                                .map(|d| {
                                    // Use last 8 chars of DID as a display name fallback.
                                    if d.len() > 8 { d[d.len()-8..].to_string() } else { d.to_string() }
                                })
                                .unwrap_or_else(|| "Agent".to_string()),
                            snippet: b.content.as_ref()
                                .and_then(|c| c.get("result"))
                                .and_then(|r| r.as_str())
                                .map(|s| s.chars().take(80).collect::<String>())
                                .unwrap_or_default(),
                        })
                        .collect()
                })
                .unwrap_or_default();

            let self_signal = *self;
            spawn_local(async move {
                if !crate::bridge::tauri_available() {
                    return;
                }

                #[derive(serde::Deserialize)]
                struct GuidePayload {
                    block_id: String,
                    summary: String,
                    suggestions: Vec<papillon_shared::GuideSuggestion>,
                }

                let result = crate::bridge::invoke::<_, GuidePayload>(
                    "canvas_generate_guide",
                    &serde_json::json!({
                        "canvasId": cid_clone,
                        "resolvedBlockSummaries": summaries,
                    }),
                ).await;

                if let Ok(payload) = result {
                    let guide_block_id = payload.block_id.clone();
                    canvases.update(|cs| {
                        if let Some(canvas) = cs.iter_mut().find(|c| c.id == cid_clone) {
                            // Upsert: update existing Guide block or prepend a new one.
                            if let Some(existing) = canvas.blocks.iter_mut()
                                .find(|b| b.id == guide_block_id)
                            {
                                existing.state = BlockState::Guide {
                                    summary: payload.summary.clone(),
                                    suggestions: payload.suggestions.clone(),
                                };
                                existing.updated_at = now_iso();
                            } else {
                                let now = now_iso();
                                let guide_block = CanvasBlock {
                                    id: guide_block_id,
                                    prompt_id: String::new(),
                                    prompt_text: None,
                                    state: BlockState::Guide {
                                        summary: payload.summary,
                                        suggestions: payload.suggestions,
                                    },
                                    schema_type: None,
                                    content: None,
                                    linked_block_ids: Vec::new(),
                                    agent_did: None,
                                    mandate_expires_at: None,
                                    preference_guided: false,
                                    auto_expand: false,
                                    retention_warning: None,
                                    created_at: now.clone(),
                                    updated_at: now,
                                };
                                // Prepend at position 0.
                                canvas.blocks.insert(0, guide_block);
                            }
                            canvas.updated_at = now_iso();
                        }
                    });
                    // Notify subscribers that a Guide block was upserted.
                    self_signal.last_event.set(Some(CanvasEvent::GuideRefreshed {
                        canvas_id: cid_clone.clone(),
                    }));
                }
            });

            let _ = guide_id; // suppress unused warning
        }
    }

    /// Load the active canvas and its blocks/messages from the SQLite DB.
    /// Creates a default canvas if none exist. No-op when Tauri is unavailable.
    pub fn load_from_db(&self) {
        if !crate::bridge::tauri_available() {
            return;
        }
        let canvases = self.canvases;
        let current_canvas_id = self.current_canvas_id;
        let canvas_messages = self.canvas_messages;

        spawn_local(async move {
            // 1. List canvases (or create one).
            let records: Vec<CanvasRecord> = match crate::bridge::invoke_no_args("canvas_list").await {
                Ok(r) => r,
                Err(e) => {
                    leptos::logging::warn!("canvas_list failed: {}", e);
                    return;
                }
            };

            let active_canvas_id: String = if records.is_empty() {
                // Create a default canvas.
                match crate::bridge::invoke::<_, CanvasRecord>(
                    "canvas_create",
                    &serde_json::json!({ "name": "My Canvas" }),
                ).await {
                    Ok(r) => {
                        let id = r.id.clone();
                        let now = r.created_at.clone();
                        let canvas = Canvas {
                            id: id.clone(),
                            name: r.name,
                            blocks: Vec::new(),
                            created_at: now.clone(),
                            updated_at: now,
                        };
                        canvases.update(|cs| cs.push(canvas));
                        current_canvas_id.set(Some(id.clone()));
                        id
                    }
                    Err(e) => {
                        leptos::logging::warn!("canvas_create failed: {}", e);
                        return;
                    }
                }
            } else {
                // Load ALL canvases into the reactive store so the sidebar is complete.
                canvases.update(|cs| merge_canvases_from_records(cs, &records));
                // Activate the first (most recent) canvas if none is already active.
                let first_id = records[0].id.clone();
                if current_canvas_id.get_untracked().is_none() {
                    current_canvas_id.set(Some(first_id.clone()));
                }
                first_id
            };

            // 2. Load blocks for the active canvas only (lazy — blocks for other
            //    canvases are loaded on demand when the user switches to them).
            match crate::bridge::invoke::<_, Vec<papillon_shared::types::CanvasBlockRecord>>(
                "canvas_blocks_load",
                &serde_json::json!({ "canvasId": active_canvas_id }),
            ).await {
                Ok(block_records) => {
                    canvases.update(|cs| {
                        if let Some(canvas) = cs.iter_mut().find(|c| c.id == active_canvas_id) {
                            for rec in block_records {
                                if canvas.blocks.iter().any(|b| b.id == rec.id) {
                                    continue;
                                }
                                let state = if rec.block_state == "resolved" {
                                    BlockState::Resolved
                                } else if rec.block_state == "note" {
                                    let parsed: Option<serde_json::Value> = rec.content_json
                                        .as_deref()
                                        .and_then(|s| serde_json::from_str(s).ok());
                                    BlockState::Note {
                                        title: parsed.as_ref()
                                            .and_then(|v| v.get("title"))
                                            .and_then(|t| t.as_str())
                                            .unwrap_or("")
                                            .to_string(),
                                        content: parsed.as_ref()
                                            .and_then(|v| v.get("note_content"))
                                            .and_then(|t| t.as_str())
                                            .unwrap_or("")
                                            .to_string(),
                                        editing: false,
                                    }
                                } else if rec.block_state.starts_with("failed") {
                                    BlockState::Failed { phase: 6, reason: rec.block_state.clone() }
                                } else {
                                    BlockState::Resolving { phase: 1, phase_label: "Loading...".into() }
                                };
                                let content: Option<serde_json::Value> = rec.content_json
                                    .as_deref()
                                    .and_then(|s| serde_json::from_str(s).ok());
                                let block = CanvasBlock {
                                    id: rec.id,
                                    prompt_id: String::new(),
                                    prompt_text: rec.prompt_text,
                                    state,
                                    schema_type: rec.schema_type,
                                    content,
                                    linked_block_ids: Vec::new(),
                                    agent_did: rec.agent_did,
                                    mandate_expires_at: rec.mandate_expires_at,
                                    preference_guided: rec.preference_guided,
                                    auto_expand: false,
                                    retention_warning: None,
                                    created_at: rec.created_at,
                                    updated_at: rec.updated_at,
                                };
                                canvas.blocks.push(block);
                            }
                        }
                    });
                }
                Err(e) => {
                    leptos::logging::warn!("canvas_blocks_load failed: {}", e);
                }
            }

            // 3. Load messages for ALL canvases so the per-canvas filter in
            //    CanvasChatThread has complete data regardless of which canvas
            //    is active.  Messages are keyed by id so we skip duplicates.
            let all_canvas_ids: Vec<String> = canvases
                .get_untracked()
                .iter()
                .map(|c| c.id.clone())
                .collect();

            for cid in all_canvas_ids {
                match crate::bridge::invoke::<_, Vec<CanvasMessageRecord>>(
                    "canvas_messages_load",
                    &serde_json::json!({ "canvasId": cid }),
                ).await {
                    Ok(msgs) => {
                        canvas_messages.update(|store| merge_messages_dedup(store, msgs));
                    }
                    Err(e) => {
                        leptos::logging::warn!("canvas_messages_load failed for {}: {}", cid, e);
                    }
                }
            }
        });
    }

    /// Record a chat message in both the reactive store and the DB.
    pub fn add_message(&self, role: &str, content: &str, block_id: Option<String>) {
        let msg_id = generate_id();
        let now = now_iso();
        let canvas_id = match self.current_canvas_id.get_untracked() {
            Some(id) => id,
            None => return,
        };

        let record = CanvasMessageRecord {
            id: msg_id.clone(),
            canvas_id: canvas_id.clone(),
            role: role.to_string(),
            content: content.to_string(),
            block_id: block_id.clone(),
            created_at: now.clone(),
        };
        self.canvas_messages.update(|ms| ms.push(record));

        let role = role.to_string();
        let content = content.to_string();
        spawn_local(async move {
            if crate::bridge::tauri_available() {
                let _ = crate::bridge::invoke::<_, serde_json::Value>(
                    "canvas_message_add",
                    &serde_json::json!({
                        "canvasId": canvas_id,
                        "role": role,
                        "content": content,
                        "blockId": block_id,
                    }),
                ).await;
            }
        });
    }
}

fn generate_id() -> String {
    let ts = js_sys::Date::now() as u64;
    let rand = (js_sys::Math::random() * 4_294_967_295.0) as u32;
    format!("{:x}-{:x}", ts, rand)
}

fn now_iso() -> String {
    js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}

fn auto_name_from_prompt(prompt: &str) -> String {
    let trimmed: String = prompt.chars().take(40).collect();
    if prompt.len() > 40 {
        format!("{}...", trimmed)
    } else {
        trimmed
    }
}

fn normalize_canvas_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_canvas_with_block(block_id: &str, content: serde_json::Value) -> Canvas {
        Canvas {
            id: "c1".into(),
            name: "Test".into(),
            blocks: vec![CanvasBlock {
                id: block_id.into(),
                prompt_id: "p1".into(),
                prompt_text: Some("original query".into()),
                state: BlockState::Resolved,
                schema_type: None,
                content: Some(content),
                linked_block_ids: Vec::new(),
                agent_did: None,
                mandate_expires_at: None,
                created_at: String::new(),
                updated_at: String::new(),
                preference_guided: false,
                auto_expand: false,
                retention_warning: None,
            }],
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn extract_block_ids_single() {
        let ids = extract_block_ids("summarize {{block:abc-123}}");
        assert_eq!(ids, vec!["abc-123"]);
    }

    #[test]
    fn extract_block_ids_multiple() {
        let ids = extract_block_ids("combine {{block:a1}} and {{block:b2}}");
        assert_eq!(ids, vec!["a1", "b2"]);
    }

    #[test]
    fn extract_block_ids_none() {
        let ids = extract_block_ids("just a normal prompt");
        assert!(ids.is_empty());
    }

    #[test]
    fn extract_block_ids_malformed() {
        let ids = extract_block_ids("{{block:unclosed");
        assert!(ids.is_empty());
    }

    #[test]
    fn expand_block_references_single() {
        let canvases = vec![make_canvas_with_block(
            "blk-1",
            serde_json::json!({"result": {"title": "Rust"}}),
        )];
        let expanded = expand_block_references("summarize {{block:blk-1}}", &canvases);
        assert!(expanded.contains("Rust"));
        assert!(!expanded.contains("{{block:"));
    }

    #[test]
    fn expand_block_references_multiple() {
        let canvases = vec![Canvas {
            id: "c1".into(),
            name: "Test".into(),
            blocks: vec![
                CanvasBlock {
                    id: "a".into(),
                    prompt_id: "p".into(),
                    prompt_text: None,
                    state: BlockState::Resolved,
                    schema_type: None,
                    content: Some(serde_json::json!({"result": "alpha"})),
                    linked_block_ids: Vec::new(),
                    agent_did: None,
                    mandate_expires_at: None,
                    created_at: String::new(),
                    updated_at: String::new(),
                    preference_guided: false,
                    auto_expand: false,
                    retention_warning: None,
                },
                CanvasBlock {
                    id: "b".into(),
                    prompt_id: "p".into(),
                    prompt_text: None,
                    state: BlockState::Resolved,
                    schema_type: None,
                    content: Some(serde_json::json!({"result": "beta"})),
                    linked_block_ids: Vec::new(),
                    agent_did: None,
                    mandate_expires_at: None,
                    created_at: String::new(),
                    updated_at: String::new(),
                    preference_guided: false,
                    auto_expand: false,
                    retention_warning: None,
                },
            ],
            created_at: String::new(),
            updated_at: String::new(),
        }];
        let expanded = expand_block_references("{{block:a}} and {{block:b}}", &canvases);
        assert!(expanded.contains("alpha"));
        assert!(expanded.contains("beta"));
        assert!(!expanded.contains("{{block:"));
    }

    #[test]
    fn expand_block_references_missing_block() {
        let canvases = vec![];
        let expanded = expand_block_references("ref {{block:missing-id}}", &canvases);
        assert!(expanded.contains("[block missing-id not found]"));
    }

    #[test]
    fn expand_block_references_no_refs() {
        let canvases = vec![];
        let text = "just a normal prompt";
        let expanded = expand_block_references(text, &canvases);
        assert_eq!(expanded, text);
    }

    // ── extract_block_ids — edge cases ────────────────────────────────────────

    #[test]
    fn extract_block_ids_empty_id_is_skipped() {
        // {{block:}} has an empty ID — should not be extracted
        let ids = extract_block_ids("{{block:}}");
        assert!(ids.is_empty());
    }

    #[test]
    fn extract_block_ids_adjacent_refs() {
        let ids = extract_block_ids("{{block:x}}{{block:y}}");
        assert_eq!(ids, vec!["x", "y"]);
    }

    // ── auto_name_from_prompt ─────────────────────────────────────────────────

    #[test]
    fn auto_name_from_prompt_short_unchanged() {
        let result = auto_name_from_prompt("hello world");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn auto_name_from_prompt_empty_is_empty() {
        let result = auto_name_from_prompt("");
        assert_eq!(result, "");
    }

    #[test]
    fn auto_name_from_prompt_exactly_40_chars_no_ellipsis() {
        let input = "1234567890123456789012345678901234567890"; // 40 ASCII chars
        assert_eq!(input.len(), 40);
        let result = auto_name_from_prompt(input);
        assert_eq!(result, input);
        assert!(!result.ends_with("..."));
    }

    #[test]
    fn auto_name_from_prompt_41_chars_truncates_with_ellipsis() {
        let input = "12345678901234567890123456789012345678901"; // 41 ASCII chars
        assert_eq!(input.len(), 41);
        let result = auto_name_from_prompt(input);
        assert!(result.ends_with("..."));
        // The truncated body should be the first 40 characters
        let body = result.trim_end_matches("...");
        assert_eq!(body.len(), 40);
        assert_eq!(body, &input[..40]);
    }

    #[test]
    fn auto_name_from_prompt_long_prompt_body_is_first_40_chars() {
        let input = "search for information about quantum computing and its applications in cryptography";
        let result = auto_name_from_prompt(input);
        assert!(result.ends_with("..."));
        let body: String = input.chars().take(40).collect();
        assert!(result.starts_with(&body));
    }

    #[test]
    fn normalize_canvas_name_trims_whitespace() {
        let result = normalize_canvas_name("  Summer travel plans  ");
        assert_eq!(result.as_deref(), Some("Summer travel plans"));
    }

    #[test]
    fn normalize_canvas_name_rejects_blank_input() {
        let result = normalize_canvas_name("   ");
        assert!(result.is_none());
    }

    // ── insert_block_ref ─────────────────────────────────────────────────────

    #[test]
    fn insert_block_ref_appends_to_empty() {
        // `CanvasState` requires a reactive runtime (RwSignal uses a leptos owner).
        // For pure-logic tests we validate the format string directly.
        let current = String::new();
        let block_id = "abc".to_string();
        let result = format!("{}{{{{block:{}}}}}", current, block_id);
        assert_eq!(result, "{{block:abc}}");
    }

    #[test]
    fn insert_block_ref_appends_to_existing() {
        let current = "search for ".to_string();
        let block_id = "xyz".to_string();
        let result = format!("{}{{{{block:{}}}}}", current, block_id);
        assert_eq!(result, "search for {{block:xyz}}");
    }

    // ── WorkflowGraph defaults ────────────────────────────────────────────────

    #[test]
    fn workflow_graph_default_is_empty() {
        let g = papillon_shared::WorkflowGraph::default();
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
        assert!(!g.is_designed);
    }
    // ── derive_map_graph ──────────────────────────────────────────────────────

    fn make_block(id: &str, prompt: &str) -> papillon_shared::CanvasBlock {
        papillon_shared::CanvasBlock {
            id: id.to_string(),
            prompt_id: id.to_string(),
            prompt_text: Some(prompt.to_string()),
            state: papillon_shared::BlockState::Resolved,
            schema_type: None,
            content: None,
            linked_block_ids: vec![],
            agent_did: None,
            created_at: String::new(),
            updated_at: String::new(),
            mandate_expires_at: None,
            preference_guided: false,
            auto_expand: false,
            retention_warning: None,
        }
    }

    #[test]
    fn derive_map_graph_creates_edge_from_block_ref() {
        let block_a = make_block("aaa", "search for flights");
        let block_b = make_block("bbb", "book using {{block:aaa}}");
        let blocks = vec![block_a, block_b];
        let graph = super::derive_map_graph(&blocks);
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
        let graph = super::derive_map_graph(&blocks);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn derive_map_graph_linked_block_ids_creates_edge() {
        let block_a = make_block("aaa", "search");
        let mut block_b = make_block("bbb", "summarize");
        block_b.linked_block_ids = vec!["aaa".to_string()];
        let blocks = vec![block_a, block_b];
        let graph = super::derive_map_graph(&blocks);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].from_node_id, "aaa");
        assert_eq!(graph.edges[0].to_node_id, "bbb");
    }

    #[test]
    fn derive_map_graph_dedupes_prompt_refs_and_linked_ids() {
        let block_a = make_block("aaa", "search");
        let mut block_b = make_block("bbb", "compare with {{block:aaa}}");
        block_b.linked_block_ids = vec!["aaa".to_string()];
        let graph = super::derive_map_graph(&[block_a, block_b]);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].from_node_id, "aaa");
        assert_eq!(graph.edges[0].to_node_id, "bbb");
    }

    #[test]
    fn derive_map_graph_empty_blocks_is_empty_graph() {
        let graph = super::derive_map_graph(&[]);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
        assert!(!graph.is_designed);
    }

}
