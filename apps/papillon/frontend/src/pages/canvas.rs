use leptos::prelude::*;
use leptos::ev;
use papillon_shared::{BlockState, CanvasBlock};

use crate::components::approval_toast::ApprovalToastStack;
use crate::components::block_renderer::BlockRenderer;
use crate::components::canvas_aside::{AsideOpen, CanvasAside, CanvasAsideDockToggle};
use crate::components::canvas_back_face::CanvasBackFace;
use crate::components::canvas_surface_title::CanvasSurfaceTitle;
use crate::components::canvas_tab_bar::CanvasTabBar;
use crate::components::hitl_gate::HitlGate;
use crate::components::inline_prompt::InlinePrompt;
use crate::components::workflow_panel::WorkflowPanel;
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
            .filter(|block| !matches!(block.state, BlockState::Guide { .. }))
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
    let aside_open = use_context::<AsideOpen>().map(|AsideOpen(open)| open).unwrap_or_else(|| RwSignal::new(false));

    let toggle_side = move |_: leptos::ev::MouseEvent| {
        canvas_state.canvas_side.update(|s| {
            *s = if *s == CanvasSide::Front {
                CanvasSide::Back
            } else {
                CanvasSide::Front
            };
        });
    };

    // Keyboard shortcut handler
    let handle_keydown = move |e: ev::KeyboardEvent| {
        if !e.ctrl_key() {
            return;
        }

        match e.key().as_str() {
            "t" | "T" => {
                e.prevent_default();
                canvas_state.new_canvas();
            }
            "w" | "W" => {
                e.prevent_default();
                if let Some(current_id) = canvas_state.current_canvas_id.get() {
                    canvas_state.delete_canvas(&current_id);
                }
            }
            "\\" => {
                e.prevent_default();
                canvas_state.workflow_panel_open.update(|open| *open = !*open);
            }
            "Tab" => {
                e.prevent_default();
                cycle_canvas_forward(&canvas_state);
            }
            _ => {}
        }
    };

    view! {
        <HitlGate />

        // Tab bar at the top with logo/settings
        <CanvasTabBar />

        <div class="canvas-page" on:keydown=handle_keydown tabindex="0">
            // Canvas header with inline prompt and workflow toggle
            <div class="canvas-header">
                <div class="canvas-header-prompt">
                    <InlinePrompt />
                </div>
                <button
                    class="canvas-flip-toggle"
                    on:click=toggle_side
                    title=move || if is_back() { "Show rendered side" } else { "Show workflow side" }
                >
                    {move || if is_back() { "↻ Show rendered" } else { "↻ Show workflow" }}
                </button>
            </div>

            // Flip container.
            <div
                class="canvas-flip-container"
                class:flipped=is_back
            >
                // Front face: rendered blocks + collapsible aside.
                <div class="canvas-face front">
                    <CanvasAsideDockToggle open=aside_open />
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
                                            // Check if this block has a container_id
                                            if block.container_id.is_some() {
                                                // TODO: Fetch BlockContainer from backend and render BlockContainerView
                                                // For now, fall back to legacy renderer
                                                view! { <BlockRenderer block_id=block.id /> }.into_any()
                                            } else {
                                                view! { <BlockRenderer block_id=block.id /> }.into_any()
                                            }
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
                    <CanvasAside open=aside_open />
                </div>

                // Back face: workflow-side surfaces.
                <div class="canvas-face back">
                    <CanvasBackFace />
                </div>
            </div>

            <WorkflowPanel />
            <ApprovalToastStack />
        </div>
    }
}

#[derive(Clone)]
enum BlockGroup {
    Single(CanvasBlock),
    Linked(Vec<CanvasBlock>),
}

/// Cycle to the next canvas in the sorted list (wrapping around).
fn cycle_canvas_forward(canvas_state: &CanvasState) {
    let current_id = match canvas_state.current_canvas_id.get() {
        Some(id) => id,
        None => return,
    };

    let mut canvases = canvas_state.canvases.get();
    // Sort by updated_at descending (most recent first) to match sidebar order
    canvases.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    let current_index = canvases.iter().position(|c| c.id == current_id);

    let next_index = match current_index {
        Some(idx) => (idx + 1) % canvases.len(),
        None => 0,
    };

    if let Some(next_canvas) = canvases.get(next_index) {
        canvas_state.current_canvas_id.set(Some(next_canvas.id.clone()));
    }
}
