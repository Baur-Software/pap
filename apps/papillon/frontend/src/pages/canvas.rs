use leptos::prelude::*;
use papillon_shared::CanvasBlock;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::components::block_renderer::BlockRenderer;
use crate::components::canvas_aside::CanvasAside;
use crate::components::canvas_back_face::CanvasBackFace;
use crate::components::canvas_empty_state::CanvasEmptyState;
use crate::components::hitl_gate::HitlGate;
use crate::state::canvas::{CanvasSide, CanvasState};

/// Loading indicator shown at the top of the canvas stream while the
/// rendering agent synthesizes workflow results into an Outcome block.
#[component]
fn SynthesisIndicator() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let pending = canvas_state.synthesis_pending;

    view! {
        <Show when=move || pending.get()>
            <div class="synthesis-indicator">
                <div class="synthesis-spinner" />
                <span>"Synthesizing workflow results..."</span>
            </div>
        </Show>
    }
}

#[component]
pub fn CanvasPage() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let aside_open = use_context::<crate::components::canvas_aside::AsideOpen>()
        .expect("AsideOpen provided at app root")
        .0;

    // Use a Memo so grouped_blocks only rebuilds when the active canvas's blocks
    // actually change — not when unrelated canvases or signals fire.
    let blocks = canvas_state.current_canvas_blocks();

    let has_blocks = move || !blocks.get().is_empty();

    // Helper: group blocks by semantic links, filtering by an ID set predicate.
    let group_blocks = |all_blocks: &[CanvasBlock], include: &dyn Fn(&str) -> bool| -> Vec<BlockGroup> {
        let mut rendered: Vec<BlockGroup> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for block in all_blocks {
            if seen.contains(&block.id) || !include(&block.id) {
                continue;
            }
            seen.insert(block.id.clone());

            if block.linked_block_ids.is_empty() {
                rendered.push(BlockGroup::Single(block.clone()));
            } else {
                let mut group = vec![block.clone()];
                for linked_id in &block.linked_block_ids {
                    if !seen.contains(linked_id) && include(linked_id) {
                        if let Some(linked) = all_blocks.iter().find(|b| b.id == *linked_id) {
                            seen.insert(linked.id.clone());
                            group.push(linked.clone());
                        }
                    }
                }
                rendered.push(BlockGroup::Linked(group));
            }
        }
        rendered
    };

    // Active blocks: not in the archived set.
    let active_blocks = move || {
        let all = blocks.get();
        let archived = canvas_state.archived_blocks.get();
        group_blocks(&all, &|id| !archived.contains(id))
    };

    // Archived blocks: in the archived set.
    let archived_blocks = move || {
        let all = blocks.get();
        let archived = canvas_state.archived_blocks.get();
        group_blocks(&all, &|id| archived.contains(id))
    };

    let has_archived = move || !archived_blocks().is_empty();
    let archive_expanded = RwSignal::new(false);
    let archived_count = move || {
        canvas_state.archived_blocks.get().len()
    };

    let is_back = move || canvas_state.canvas_side.get() == CanvasSide::Back;

    // ── Workflow graph sync ─────────────────────────────────────────────
    // Keep the MAP-mode workflow graph in sync as blocks resolve or change.
    Effect::new(move || {
        let current_blocks = blocks.get();
        let graph = crate::state::canvas::derive_map_graph(&current_blocks);
        canvas_state.workflow_graph.set(graph);
    });

    // ── Global keyboard shortcuts ───────────────────────────────────────
    // Registered on `window` so they work regardless of focus target.
    // Shortcuts that act on a specific block only fire when a block is focused.
    {
        let cs = canvas_state;
        let on_keydown = Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
            let key = e.key();
            let ctrl_or_meta = e.ctrl_key() || e.meta_key();

            // Ctrl/Cmd+K — focus the address bar
            if ctrl_or_meta && key == "k" {
                e.prevent_default();
                e.stop_propagation();
                cs.focus_prompt.update(|n| *n += 1);
                return;
            }

            // Ctrl/Cmd+Z — undo last action
            if ctrl_or_meta && key == "z" && !e.shift_key() {
                e.prevent_default();
                cs.undo();
                return;
            }

            // Escape — clear selection, close modals, cancel wiring
            if key == "Escape" {
                cs.focused_block_id.set(None);
                cs.hitl_pending.set(None);
                cs.reshape_block_id.set(None);
                return;
            }

            // Block-specific shortcuts — only when a block has focus
            if let Some(block_id) = cs.focused_block_id.get_untracked() {
                // Delete / Backspace — delete focused block
                if key == "Delete" || key == "Backspace" {
                    // Don't intercept when typing in an input/textarea
                    if let Some(target) = e.target() {
                        if let Ok(el) = target.dyn_into::<web_sys::HtmlElement>() {
                            let tag = el.tag_name().to_uppercase();
                            if tag == "INPUT" || tag == "TEXTAREA" || el.is_content_editable() {
                                return;
                            }
                        }
                    }
                    e.prevent_default();
                    cs.delete_block(&block_id);
                    return;
                }

                // Shift+P — toggle pin on focused block
                if e.shift_key() && key == "P" {
                    e.prevent_default();
                    cs.toggle_pin(&block_id);
                    return;
                }
            }
        });

        web_sys::window()
            .unwrap()
            .add_event_listener_with_callback("keydown", on_keydown.as_ref().unchecked_ref())
            .unwrap();
        on_keydown.forget(); // Leak — lives as long as the page
    }

    // ── Drop zone handlers ──────────────────────────────────────────────
    let on_dragover = move |e: web_sys::DragEvent| {
        e.prevent_default();
    };
    let on_drop = move |e: web_sys::DragEvent| {
        e.prevent_default();
        if let Some(dt) = e.data_transfer() {
            if let Ok(text) = dt.get_data("text/plain") {
                if text.contains("{{block:") {
                    // Extract block ID from {{block:ID}} pattern
                    if let Some(start) = text.find("{{block:") {
                        let after = &text[start + 8..];
                        if let Some(end) = after.find("}}") {
                            let ref_id = &after[..end];
                            if !ref_id.is_empty() {
                                canvas_state.insert_block_ref(ref_id.to_string());
                            }
                        }
                    }
                }
            }
        }
    };

    view! {
        <HitlGate />

        <div class="canvas-page">
            // Flip container.
            <div
                class="canvas-flip-container"
                class:flipped=is_back
            >
                // Front face: rendered blocks + collapsible aside.
                <div class="canvas-face front">
                    <div class="canvas-page-with-aside">
                        <div
                            class="canvas-stream"
                            on:dragover=on_dragover
                            on:drop=on_drop
                        >
                            <SynthesisIndicator />
                            <Show
                                when=has_blocks
                                fallback=move || view! { <CanvasEmptyState /> }
                            >
                                <For
                                    each=active_blocks
                                    key=|g| match g {
                                        BlockGroup::Single(b) => format!("{}@{}", b.id, b.updated_at),
                                        BlockGroup::Linked(bs) => bs
                                            .iter()
                                            .map(|b| format!("{}@{}", b.id, b.updated_at))
                                            .collect::<Vec<_>>()
                                            .join("-"),
                                    }
                                    children=move |group| {
                                        match group {
                                            BlockGroup::Single(block) => {
                                                view! { <BlockRenderer block_id=block.id /> }.into_any()
                                            }
                                            BlockGroup::Linked(blocks) => {
                                                view! {
                                                    <div class="block-group">
                                                        {blocks.into_iter().map(|block| {
                                                            view! { <BlockRenderer block_id=block.id /> }
                                                        }).collect::<Vec<_>>()}
                                                    </div>
                                                }
                                                .into_any()
                                            }
                                        }
                                    }
                                />
                                // Archive section — shown when there are archived blocks.
                                <Show when=has_archived>
                                    <div class="canvas-archive-section">
                                        <button
                                            class="archive-toggle"
                                            on:click=move |_| archive_expanded.update(|v| *v = !*v)
                                        >
                                            {move || {
                                                if archive_expanded.get() {
                                                    "\u{25bc} Past".to_string()
                                                } else {
                                                    format!("\u{25b6} Past ({} archived)", archived_count())
                                                }
                                            }}
                                        </button>
                                        <Show when=move || archive_expanded.get()>
                                            <For
                                                each=archived_blocks
                                                key=|g| match g {
                                                    BlockGroup::Single(b) => format!("arch-{}@{}", b.id, b.updated_at),
                                                    BlockGroup::Linked(bs) => bs
                                                        .iter()
                                                        .map(|b| format!("arch-{}@{}", b.id, b.updated_at))
                                                        .collect::<Vec<_>>()
                                                        .join("-"),
                                                }
                                                children=move |group| {
                                                    match group {
                                                        BlockGroup::Single(block) => {
                                                            view! { <BlockRenderer block_id=block.id /> }.into_any()
                                                        }
                                                        BlockGroup::Linked(blocks) => {
                                                            view! {
                                                                <div class="block-group">
                                                                    {blocks.into_iter().map(|block| {
                                                                        view! { <BlockRenderer block_id=block.id /> }
                                                                    }).collect::<Vec<_>>()}
                                                                </div>
                                                            }
                                                            .into_any()
                                                        }
                                                    }
                                                }
                                            />
                                        </Show>
                                    </div>
                                </Show>
                            </Show>
                            <button
                                class="add-note-btn"
                                title="Add a note"
                                on:click=move |_| canvas_state.create_note(String::new(), String::new())
                            >
                                "+ Note"
                            </button>
                        </div>
                        <CanvasAside open=aside_open />
                    </div>
                </div>

                // Back face: three-tab panel — Sources / Build / History.
                <div class="canvas-face back">
                    <CanvasBackFace />
                </div>
            </div>
        </div>
    }
}

#[derive(Clone)]
enum BlockGroup {
    Single(CanvasBlock),
    Linked(Vec<CanvasBlock>),
}
