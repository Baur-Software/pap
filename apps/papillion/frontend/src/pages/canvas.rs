use leptos::prelude::*;

use crate::components::block_renderer::BlockRenderer;
use crate::state::canvas::CanvasState;

const INSPIRATION_LINES: &[&str] = &[
    "People are booking travel without giving away their passport number",
    "Your agents built this page. No one built a profile on you.",
    "The token economy is on your machine",
];

#[component]
pub fn CanvasPage() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks)
            .unwrap_or_default()
    };

    let has_blocks = move || !blocks().is_empty();

    // Open palette on first visit if no canvases exist
    Effect::new(move || {
        if canvas_state.canvases.get().is_empty() && !canvas_state.palette_open.get() {
            canvas_state.palette_open.set(true);
        }
    });

    // Group blocks by semantic links for rendering
    let grouped_blocks = move || {
        let all_blocks = blocks();
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

    view! {
        <div class="canvas-area">
            <Show when=has_blocks fallback=move || view! {
                <div class="canvas-empty">
                    <div class="canvas-inspiration">
                        {INSPIRATION_LINES.iter().map(|&line| {
                            view! { <div class="inspiration-line">{line}</div> }
                        }).collect::<Vec<_>>()}
                    </div>
                    <div class="canvas-shortcut-hint">
                        "Press " <kbd>"\u{2318}K"</kbd> " to start building"
                    </div>
                </div>
            }>
                <div class="canvas-blocks">
                    <For
                        each=grouped_blocks
                        key=|g| match g {
                            BlockGroup::Single(b) => b.id.clone(),
                            BlockGroup::Linked(bs) => bs.iter().map(|b| b.id.as_str()).collect::<Vec<_>>().join("-"),
                        }
                        let:group
                    >
                        {match group {
                            BlockGroup::Single(block) => {
                                view! { <BlockRenderer block=block /> }.into_any()
                            }
                            BlockGroup::Linked(blocks) => {
                                view! {
                                    <div class="block-group">
                                        {blocks.into_iter().map(|block| {
                                            view! { <BlockRenderer block=block /> }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                }.into_any()
                            }
                        }}
                    </For>
                </div>
            </Show>
        </div>
    }
}

#[derive(Clone)]
enum BlockGroup {
    Single(papillion_shared::CanvasBlock),
    Linked(Vec<papillion_shared::CanvasBlock>),
}
