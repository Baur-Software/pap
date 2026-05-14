use leptos::prelude::*;

use crate::state::canvas::CanvasState;

/// Browser-style tab bar for canvas navigation.
/// Shows the first 4 canvases sorted by `updated_at` (most recent first).
/// Remaining canvases appear in an overflow dropdown.
#[component]
pub fn CanvasTabBar() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let on_new_canvas = move |_: leptos::ev::MouseEvent| {
        canvas_state.new_canvas();
    };

    view! {
        <div class="canvas-tab-bar">
            <div class="canvas-tabs">
                <For
                    each=move || {
                        let mut canvases = canvas_state.canvases.get();
                        canvases.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                        canvases.into_iter().take(4).collect::<Vec<_>>()
                    }
                    key=|c| c.id.clone()
                    children=move |canvas| {
                        let id = canvas.id.clone();
                        view! {
                            <CanvasTab canvas_id=id name=canvas.name />
                        }
                    }
                />
                {move || {
                    let mut canvases = canvas_state.canvases.get();
                    canvases.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                    let overflow: Vec<_> = canvases.into_iter().skip(4).collect();
                    if !overflow.is_empty() {
                        Some(view! {
                            <OverflowDropdown canvases=overflow />
                        })
                    } else {
                        None
                    }
                }}
            </div>
            <button
                class="canvas-tab-new"
                on:click=on_new_canvas
                title="New canvas"
            >
                "+"
            </button>
        </div>
    }
}

/// Individual canvas tab.
#[component]
fn CanvasTab(canvas_id: String, name: String) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let is_active = Memo::new({
        let id = canvas_id.clone();
        move |_| canvas_state.current_canvas_id.get().as_deref() == Some(&id)
    });

    let display_name = if name.len() > 20 {
        format!("{}…", &name[..20])
    } else {
        name
    };

    let id_for_click = canvas_id.clone();
    let on_click = move |_: leptos::ev::MouseEvent| {
        canvas_state.current_canvas_id.set(Some(id_for_click.clone()));
    };

    let id_for_close = canvas_id.clone();
    let on_close = move |e: leptos::ev::MouseEvent| {
        e.stop_propagation();
        canvas_state.delete_canvas(&id_for_close);
    };

    view! {
        <div
            class="canvas-tab"
            class:active=move || is_active.get()
            on:click=on_click
        >
            <span class="canvas-tab-name">{display_name}</span>
            <button
                class="canvas-tab-close"
                on:click=on_close
                title="Close canvas"
            >
                "\u{00d7}"
            </button>
        </div>
    }
}

/// Dropdown for canvases beyond the first 4.
#[component]
fn OverflowDropdown(canvases: Vec<papillon_shared::Canvas>) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let open = RwSignal::new(false);

    let toggle = move |_: leptos::ev::MouseEvent| {
        open.update(|o| *o = !*o);
    };

    view! {
        <div class="canvas-tab-overflow">
            <button
                class="canvas-tab-overflow-btn"
                on:click=toggle
                title="More canvases"
            >
                "⋯"
            </button>
            {move || {
                if open.get() {
                    let canvas_list = canvases.clone();
                    Some(view! {
                        <div class="canvas-tab-overflow-menu">
                            <For
                                each=move || canvas_list.clone()
                                key=|c| c.id.clone()
                                children=move |canvas| {
                                    let id_for_click = canvas.id.clone();
                                    let relative_time = format_relative_time(&canvas.updated_at);
                                    let on_item_click = move |_: leptos::ev::MouseEvent| {
                                        canvas_state.current_canvas_id.set(Some(id_for_click.clone()));
                                        open.set(false);
                                    };
                                    view! {
                                        <button
                                            class="canvas-tab-overflow-item"
                                            on:click=on_item_click
                                        >
                                            <span class="overflow-item-name">{canvas.name}</span>
                                            <span class="overflow-item-time">{relative_time}</span>
                                        </button>
                                    }
                                }
                            />
                        </div>
                    })
                } else {
                    None
                }
            }}
        </div>
    }
}

/// Format a timestamp as a relative time string (e.g., "2m ago", "1h ago").
fn format_relative_time(iso_timestamp: &str) -> String {
    let now = js_sys::Date::now();
    let then = js_sys::Date::parse(iso_timestamp);
    if then.is_nan() {
        return String::new();
    }
    let delta_ms = now - then;
    let delta_sec = (delta_ms / 1000.0) as i64;

    if delta_sec < 60 {
        "just now".into()
    } else if delta_sec < 3600 {
        format!("{}m ago", delta_sec / 60)
    } else if delta_sec < 86400 {
        format!("{}h ago", delta_sec / 3600)
    } else {
        format!("{}d ago", delta_sec / 86400)
    }
}
