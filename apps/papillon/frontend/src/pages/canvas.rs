use leptos::prelude::*;
use papillon_shared::CanvasBlock;

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
                        <div class="canvas-stream">
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
