use leptos::prelude::*;

use crate::state::canvas::CanvasState;

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

/// Empty-state capability tiles — shown when the canvas has no blocks.
/// Each tile prefills the prompt bar so the user can complete and submit.
#[component]
pub fn CanvasEmptyState() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    view! {
        <div class="canvas-empty-state">
            <div class="agent-tiles">
                {AGENT_TILES.iter().map(|&(label, example)| {
                    let canvas_state = canvas_state;
                    view! {
                        <button
                            class="agent-tile"
                            on:click=move |_| {
                                canvas_state.prefill_prompt.set(Some(example.to_string()));
                                canvas_state.focus_prompt.update(|n| *n += 1);
                            }
                        >
                            <span class="agent-tile-label">{label}</span>
                            <span class="agent-tile-example">{example}</span>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }
}
