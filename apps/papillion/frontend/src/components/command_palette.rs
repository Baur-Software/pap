use leptos::prelude::*;
use leptos::{ev, html};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::state::canvas::CanvasState;

const GHOST_EXAMPLES: &[&str] = &[
    "Book a flight SAN \u{2192} SJC",
    "Compare hotel rates in Tokyo",
    "Find a PAP-compatible payment agent",
    "Search the web without disclosure",
    "Ask AI about zero-trust protocols",
];

#[component]
pub fn CommandPalette() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let input_ref = NodeRef::<html::Input>::new();
    let input_value = RwSignal::new(String::new());

    let is_open = move || canvas_state.palette_open.get();
    let reshape_context = move || canvas_state.reshape_block_id.get();

    let close = move |_| {
        canvas_state.palette_open.set(false);
        canvas_state.reshape_block_id.set(None);
        input_value.set(String::new());
    };

    let submit = move || {
        let text = input_value.get();
        if text.trim().is_empty() {
            return;
        }
        canvas_state.submit_prompt(text.clone());
        canvas_state.palette_open.set(false);
        canvas_state.reshape_block_id.set(None);
        input_value.set(String::new());
    };

    let on_keydown = move |e: ev::KeyboardEvent| {
        if e.key() == "Escape" {
            canvas_state.palette_open.set(false);
            canvas_state.reshape_block_id.set(None);
            input_value.set(String::new());
        } else if e.key() == "Enter" {
            submit();
        }
    };

    let click_suggestion = move |text: &'static str| {
        input_value.set(text.to_string());
        // Auto-focus back to input
        if let Some(el) = input_ref.get() {
            let _ = el.focus();
        }
    };

    // Auto-focus when palette opens — delay ensures <Show> has rendered the input
    Effect::new(move || {
        if canvas_state.palette_open.get() {
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
        }
    });

    view! {
        <Show when=is_open>
            <div class="palette-overlay" on:click=close>
                <div class="palette" on:click=move |e| e.stop_propagation()>
                    <div class="palette-header">
                        <span class="palette-icon">"\u{2318}"</span>
                        <span class="palette-label">"What do you want to build?"</span>
                    </div>
                    <Show when=move || reshape_context().is_some()>
                        <div class="palette-context">
                            "Reshaping block"
                        </div>
                    </Show>
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
                    <Show when=move || input_value.get().is_empty() && reshape_context().is_none()>
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
            </div>
        </Show>
    }
}
