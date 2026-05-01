use leptos::{ev, html, prelude::*};

use crate::state::canvas::CanvasState;

fn current_canvas_name(canvas_state: CanvasState) -> String {
    canvas_state
        .current_canvas()
        .map(|canvas| canvas.name)
        .unwrap_or_default()
}

fn commit_canvas_name(canvas_state: CanvasState, draft: RwSignal<String>, editing: RwSignal<bool>) {
    let current_name = current_canvas_name(canvas_state);
    let next_name = draft.get_untracked().trim().to_string();

    if next_name.is_empty() {
        draft.set(current_name);
        editing.set(false);
        return;
    }

    if next_name != current_name {
        canvas_state.rename_current_canvas(next_name.clone());
    }

    draft.set(next_name);
    editing.set(false);
}

fn cancel_canvas_rename(
    canvas_state: CanvasState,
    draft: RwSignal<String>,
    editing: RwSignal<bool>,
) {
    draft.set(current_canvas_name(canvas_state));
    editing.set(false);
}

#[component]
pub fn CanvasSurfaceTitle() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let editing = RwSignal::new(false);
    let draft = RwSignal::new(String::new());
    let input_ref = NodeRef::<html::Input>::new();

    Effect::new(move |_| {
        if !editing.get() {
            draft.set(current_canvas_name(canvas_state));
        }
    });

    Effect::new(move |_| {
        if editing.get() {
            if let Some(input) = input_ref.get() {
                let _ = input.focus();
                let _ = input.select();
            }
        }
    });

    view! {
        <Show when=move || canvas_state.current_canvas().is_some()>
            <div class="canvas-surface-head">
                <Show
                    when=move || editing.get()
                    fallback=move || {
                        view! {
                            <button
                                class="canvas-title-button"
                                title="Rename canvas"
                                on:click=move |_| editing.set(true)
                            >
                                {move || current_canvas_name(canvas_state)}
                            </button>
                        }
                    }
                >
                    <input
                        node_ref=input_ref
                        class="canvas-title-input"
                        prop:value=draft
                        spellcheck="false"
                        on:input=move |ev| draft.set(event_target_value(&ev))
                        on:blur=move |_| commit_canvas_name(canvas_state, draft, editing)
                        on:keydown=move |ev: ev::KeyboardEvent| match ev.key().as_str() {
                            "Enter" => {
                                ev.prevent_default();
                                commit_canvas_name(canvas_state, draft, editing);
                            }
                            "Escape" => {
                                ev.prevent_default();
                                cancel_canvas_rename(canvas_state, draft, editing);
                            }
                            _ => {}
                        }
                    />
                </Show>
            </div>
        </Show>
    }
}
