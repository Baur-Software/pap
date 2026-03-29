use leptos::prelude::*;
use papillon_shared::{BlockState, Canvas, CanvasBlock};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::service::PapillonService;
use crate::state::registry::RegistryState;

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
        }
    }
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

    /// Seed the first-ever canvas with live agent queries so the app
    /// opens with real content resolving through the handshake pipeline.
    pub fn seed_first_canvas(&self) {
        const SEED_PROMPTS: &[&str] = &[
            "hacker news",
            "define protocol",
            "tell me about decentralized identity",
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

    /// Get the currently active canvas, if any.
    pub fn current_canvas(&self) -> Option<Canvas> {
        let id = self.current_canvas_id.get()?;
        self.canvases.get().into_iter().find(|c| c.id == id)
    }

    /// Submit a new prompt — creates blocks via the backend.
    pub fn submit_prompt(&self, text: String) {
        let canvases = self.canvases;
        let current_id = self.current_canvas_id;
        let recent = self.recent_prompts;

        // Track recent prompts (max 10)
        recent.update(|r| {
            r.retain(|p| p != &text);
            r.insert(0, text.clone());
            r.truncate(10);
        });

        let prompt_id = generate_id();

        // Auto-rename untitled canvases from the first prompt
        if let Some(id) = current_id.get() {
            canvases.update(|cs| {
                if let Some(c) = cs.iter_mut().find(|c| c.id == id) {
                    if c.name == "Untitled canvas" && c.blocks.is_empty() {
                        c.name = auto_name_from_prompt(&text);
                    }
                }
            });
        }

        let canvas_id = current_id.get().unwrap_or_else(|| {
            // Create a new canvas auto-named from the prompt
            let new_id = generate_id();
            let name = auto_name_from_prompt(&text);
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

        // Extract block references and expand them for the backend
        let all_canvases = canvases.get();
        let linked_block_ids = extract_block_ids(&text);
        let expanded_text = expand_block_references(&text, &all_canvases);

        // Create a resolving block immediately (optimistic UI)
        let block = CanvasBlock {
            id: generate_id(),
            prompt_id: prompt_id.clone(),
            prompt_text: Some(text),
            state: BlockState::Resolving {
                phase: 1,
                phase_label: "Discovering agents...".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids,
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

        // Fire backend command with expanded text
        let cid = canvas_id.clone();

        // Capture Leptos contexts now (in the component scope) — spawn_local
        // runs outside reactive ownership so expect_context would panic there.
        let service = use_context::<std::sync::Arc<dyn PapillonService>>();
        let registry = use_context::<RegistryState>();

        spawn_local(async move {
            let result = if bridge::tauri_available() {
                // Tauri IPC path — delegates to native backend handshake
                #[derive(serde::Serialize)]
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
                bridge::invoke::<_, serde_json::Value>("canvas_prompt", &args)
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
                // Mark block as failed
                canvases.update(|cs| {
                    if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                        if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == block_id) {
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
        let original_text = canvases
            .get()
            .iter()
            .flat_map(|c| c.blocks.iter())
            .find(|b| b.id == block_id)
            .and_then(|b| b.prompt_text.clone())
            .unwrap_or_default();

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
            struct RetryArgs {
                canvas_id: String,
                block_id: String,
                original_text: String,
            }
            let args = RetryArgs {
                canvas_id: cid.clone(),
                block_id: bid.clone(),
                original_text,
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

    /// Apply a streaming phase update from the backend.
    /// Searches all canvases for the block by ID, preserving prompt_text
    /// and other frontend-only fields that the backend doesn't have.
    pub fn apply_block_event(&self, event_block: CanvasBlock) {
        self.canvases.update(|cs| {
            for canvas in cs.iter_mut() {
                if let Some(b) = canvas.blocks.iter_mut().find(|b| b.id == event_block.id) {
                    // Preserve prompt_text — backend phase events don't carry it
                    let prompt_text = b.prompt_text.take();
                    let linked = std::mem::take(&mut b.linked_block_ids);
                    *b = event_block;
                    if b.prompt_text.is_none() {
                        b.prompt_text = prompt_text;
                    }
                    if b.linked_block_ids.is_empty() {
                        b.linked_block_ids = linked;
                    }
                    canvas.updated_at = now_iso();
                    return;
                }
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
                created_at: String::new(),
                updated_at: String::new(),
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
                    created_at: String::new(),
                    updated_at: String::new(),
                },
                CanvasBlock {
                    id: "b".into(),
                    prompt_id: "p".into(),
                    prompt_text: None,
                    state: BlockState::Resolved,
                    schema_type: None,
                    content: Some(serde_json::json!({"result": "beta"})),
                    linked_block_ids: Vec::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
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
}
