use leptos::prelude::*;
use leptos::{ev, html};
use leptos_router::hooks::use_navigate;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::components::block_renderer::BlockRenderer;
use crate::state::canvas::CanvasState;
use crate::state::orchestrator::OrchestratorState;
use papillion_shared::OrchestratorStatus;

const INSPIRATION_LINES: &[&str] = &[
    "People are booking travel without giving away their passport number",
    "Your agents built this page. No one built a profile on you.",
    "The token economy is on your machine",
];

const GHOST_EXAMPLES: &[&str] = &[
    "Book a flight SAN \u{2192} SJC",
    "Compare hotel rates in Tokyo",
    "Find a PAP-compatible payment agent",
    "Search the web without disclosure",
    "Ask AI about zero-trust protocols",
];

#[component]
pub fn CanvasPage() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let orchestrator = expect_context::<OrchestratorState>();

    let blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks)
            .unwrap_or_default()
    };

    let has_blocks = move || !blocks().is_empty();

    let is_ready = move || matches!(
        orchestrator.status.get(),
        OrchestratorStatus::Ready
    );

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
                    <Show
                        when=is_ready
                        fallback=move || view! { <SetupPrompt /> }
                    >
                        <InlinePrompt />
                    </Show>
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
                // Inline prompt at bottom when blocks exist
                <InlinePrompt />
            </Show>
        </div>
    }
}

/// Prompt input embedded directly in the canvas — not an overlay.
#[component]
fn InlinePrompt() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let input_ref = NodeRef::<html::Input>::new();
    let input_value = RwSignal::new(String::new());

    let submit = move || {
        let text = input_value.get();
        if text.trim().is_empty() {
            return;
        }
        canvas_state.submit_prompt(text.clone());
        input_value.set(String::new());
    };

    let on_keydown = move |e: ev::KeyboardEvent| {
        if e.key() == "Enter" {
            submit();
        }
    };

    let click_suggestion = move |text: &'static str| {
        input_value.set(text.to_string());
        if let Some(el) = input_ref.get() {
            let _ = el.focus();
        }
    };

    // Focus the input on mount and whenever focus_prompt is bumped (e.g. ⌘K)
    Effect::new(move || {
        let _ = canvas_state.focus_prompt.get(); // subscribe to signal
        let ir = input_ref;
        let cb = Closure::once(move || {
            if let Some(el) = ir.get() {
                let _ = el.focus();
            }
        });
        let window = web_sys::window().unwrap();
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.as_ref().unchecked_ref(),
            50,
        );
        cb.forget();
    });

    view! {
        <div class="canvas-prompt">
            <div class="canvas-prompt-header">
                <span class="palette-icon">{"\u{2318}"}</span>
                <span class="palette-label">"What do you want to build?"</span>
            </div>
            <input
                node_ref=input_ref
                class="palette-input"
                type="text"
                placeholder="Type your prompt..."
                prop:value=move || input_value.get()
                on:input=move |e| {
                    input_value.set(event_target_value(&e));
                }
                on:keydown=on_keydown
            />
            <Show when=move || input_value.get().is_empty()>
                <div class="palette-suggestions">
                    {GHOST_EXAMPLES.iter().map(|&text| {
                        let t = text;
                        view! {
                            <button
                                class="palette-suggestion"
                                on:click=move |_| click_suggestion(t)
                            >
                                {t}
                            </button>
                        }
                    }).collect::<Vec<_>>()}
                </div>
            </Show>
        </div>
    }
}

/// Shown when LLM isn't configured — directs user to Settings.
#[component]
fn SetupPrompt() -> impl IntoView {
    let navigate = use_navigate();

    view! {
        <div class="canvas-prompt canvas-prompt-setup">
            <h2 class="setup-heading">"Configure an LLM provider to start building."</h2>
            <p class="setup-description">
                "The orchestrator needs a language model to route prompts to agents. "
                "Choose built-in (on-device) or connect an external provider."
            </p>
            <button class="btn btn-primary" on:click=move |_| {
                let nav = navigate.clone();
                nav("/settings", Default::default());
            }>
                "Open Settings"
            </button>
        </div>
    }
}

#[derive(Clone)]
enum BlockGroup {
    Single(papillion_shared::CanvasBlock),
    Linked(Vec<papillion_shared::CanvasBlock>),
}
