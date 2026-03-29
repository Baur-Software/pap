use leptos::prelude::*;
use leptos::{ev, html};
use leptos_router::hooks::use_navigate;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::components::block_renderer::BlockRenderer;
use crate::state::canvas::CanvasState;
use crate::state::orchestrator::OrchestratorState;
use papillon_shared::OrchestratorStatus;

/// Try-it-now prompts that match real intent rules in `papillon_shared::intent`.
const QUICK_PROMPTS: &[&str] = &[
    "search for Rust programming",
    "weather in Tokyo",
    "define ephemeral",
    "paper on zero-knowledge proofs",
    "tell me about photosynthesis",
    "convert 100 USD to EUR",
];

/// Agent capabilities shown as clickable tiles on the new-tab canvas.
/// Each entry is (label, example_prompt).
const AGENT_TILES: &[(&str, &str)] = &[
    ("Web Search", "search for "),
    ("Wikipedia", "tell me about "),
    ("Weather", "weather in "),
    ("Dictionary", "define "),
    ("Currency", "convert 100 USD to EUR"),
    ("Countries", "country "),
    ("Research Papers", "paper on "),
    ("GitHub Repos", "github "),
    ("Books", "book about "),
    ("Hacker News", "hacker news "),
    ("Geocoding", "where is "),
    ("Web Reader", "https://"),
    ("AI Chat", "explain "),
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
                <NewTabCanvas />
            }>
                <div class="canvas-blocks">
                    <For
                        each=grouped_blocks
                        key=|g| match g {
                            BlockGroup::Single(b) => format!("{}@{}", b.id, b.updated_at),
                            BlockGroup::Linked(bs) => bs.iter().map(|b| format!("{}@{}", b.id, b.updated_at)).collect::<Vec<_>>().join("-"),
                        }
                        children=move |group| {
                            match group {
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
                            }
                        }
                    />
                </div>
                <InlinePrompt />
            </Show>
        </div>
    }
}

/// The empty canvas — like a new tab page in a browser.
/// Shows the prompt bar, available agents, and quick-start actions.
#[component]
fn NewTabCanvas() -> impl IntoView {
    let orchestrator = expect_context::<OrchestratorState>();
    let navigate = use_navigate();

    let is_unconfigured =
        move || matches!(orchestrator.status.get(), OrchestratorStatus::Unconfigured);
    let is_disconnected =
        move || matches!(orchestrator.status.get(), OrchestratorStatus::Disconnected);

    let nav = navigate.clone();
    let go_browse = move |_| {
        let n = nav.clone();
        n("/browse", Default::default());
    };

    view! {
        <div class="canvas-empty">
            <div class="newtab-hero">
                <img src="/logo.png" alt="" class="newtab-logo" />
                <p class="newtab-tagline">
                    "The browser for the agent web"
                </p>
            </div>

            <p class="inspiration-line">"Search the web, check the weather, or explore knowledge \u{2014} all through privacy-preserving agents."</p>

            <Show when=is_disconnected>
                <div class="canvas-prompt-setup">
                    <p>"Configure an LLM provider to unlock on-device AI capabilities."</p>
                    <a href="/settings" class="newtab-link">"Open Settings"</a>
                </div>
            </Show>

            <Show when=move || !is_disconnected()>
                <InlinePrompt />
            </Show>

            <Show when=is_unconfigured>
                <div class="newtab-setup-hint">
                    "On-device AI not configured yet \u{2014} "
                    "search, weather, wiki, and 10 more agents work without it. "
                    <a href="/settings" class="newtab-link">"Set up AI"</a>
                </div>
            </Show>

            <div class="agent-capabilities">
                <div class="capabilities-label">"Agents available now"</div>
                <AgentTiles />
            </div>

            <div class="newtab-footer">
                <button class="newtab-action" on:click=go_browse>
                    "Browse Registries"
                </button>
                <span class="newtab-hint">
                    {"\u{2318}K new canvas"}
                </span>
            </div>
        </div>
    }
}

/// Grid of clickable agent capability tiles.
/// Each tile populates the prompt input with an example query via signal.
#[component]
fn AgentTiles() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    view! {
        <div class="capabilities-grid">
            {AGENT_TILES.iter().map(|&(label, example)| {
                let cs = canvas_state;
                let ex = example.to_string();
                view! {
                    <button
                        class="capability-chip"
                        on:click=move |_| {
                            cs.prefill_prompt.set(Some(ex.clone()));
                            cs.focus_prompt.set(cs.focus_prompt.get_untracked() + 1);
                        }
                    >
                        {label}
                    </button>
                }
            }).collect::<Vec<_>>()}
        </div>
    }
}

/// Prompt input embedded directly in the canvas — the address bar of the agent web.
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

    // Pick up prefill values from agent tile clicks
    Effect::new(move || {
        if let Some(text) = canvas_state.prefill_prompt.get() {
            input_value.set(text);
            canvas_state.prefill_prompt.set(None);
        }
    });

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
        let _ = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 50);
        cb.forget();
    });

    view! {
        <div class="canvas-prompt">
            <span class="palette-label">"What do you want to build?"</span>
            <input
                node_ref=input_ref
                class="palette-input"
                type="text"
                placeholder="Search agents, ask a question, or enter a pap:// address\u{2026}"
                prop:value=move || input_value.get()
                on:input=move |e| {
                    input_value.set(event_target_value(&e));
                }
                on:keydown=on_keydown
            />
            <Show when=move || input_value.get().is_empty()>
                <div class="palette-suggestions">
                    {QUICK_PROMPTS.iter().map(|&text| {
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

#[derive(Clone)]
enum BlockGroup {
    Single(papillon_shared::CanvasBlock),
    Linked(Vec<papillon_shared::CanvasBlock>),
}
