use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock};

use crate::components::block_renderer::BlockRenderer;
use crate::components::canvas_back_face::CanvasBackFace;
use crate::components::canvas_surface_title::CanvasSurfaceTitle;
use crate::components::hitl_gate::HitlGate;
use crate::state::canvas::{CanvasSide, CanvasState};

#[component]
pub fn CanvasPage() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    // Use a Memo so grouped_blocks only rebuilds when the active canvas's blocks
    // actually change — not when unrelated canvases or signals fire.
    let blocks = canvas_state.current_canvas_blocks();

    let rendered_blocks = move || {
        blocks
            .get()
            .into_iter()
            .filter(|block| matches!(block.state, BlockState::Resolved | BlockState::Outcome { .. }))
            .collect::<Vec<_>>()
    };
    let has_rendered_blocks = move || !rendered_blocks().is_empty();
    // Group blocks by semantic links for rendering
    let grouped_blocks = move || {
        let all_blocks = rendered_blocks();
        let mut rendered: Vec<BlockGroup> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for block in &all_blocks {
            if seen.contains(&block.id) {
                continue;
            }
            seen.insert(block.id.clone());

            if block.linked_block_ids.is_empty() {
                rendered.push(BlockGroup::Single(block.clone()));
            } else {
                let mut group = vec![block.clone()];
                for linked_id in &block.linked_block_ids {
                    if !seen.contains(linked_id) {
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
                    <div class="canvas-stream">
                        <CanvasSurfaceTitle />
                        <Show when=move || !has_rendered_blocks()>
                            <div class="canvas-surface-status">"Approve workflow to render"</div>
                        </Show>
                        <Show when=has_rendered_blocks>
                            <For
                                each=grouped_blocks
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
                        </Show>
                        <Show when=has_rendered_blocks>
                            <button
                                class="add-note-btn"
                                title="Add a note"
                                on:click=move |_| canvas_state.create_note(String::new(), String::new())
                            >
                                "+ Note"
                            </button>
                        </Show>
                    </div>
                </div>

                // Back face: workflow-side surfaces.
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
