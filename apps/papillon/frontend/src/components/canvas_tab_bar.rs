use leptos::prelude::*;

use crate::state::canvas::CanvasState;

/// Browser-style tab bar for canvas navigation.
/// Shows the first 4 canvases sorted by `updated_at` (most recent first).
/// Remaining canvases appear in an overflow dropdown.
#[component]
pub fn CanvasTabBar() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let menu_open = RwSignal::new(false);

    let on_new_canvas = move |_: leptos::ev::MouseEvent| {
        canvas_state.new_canvas();
    };

    let toggle_menu = move |_: leptos::ev::MouseEvent| {
        menu_open.update(|v| *v = !*v);
    };

    view! {
        <div class="canvas-tab-bar">
            // Logo/brand button - opens settings panel
            <button
                class="canvas-tab-brand"
                on:click=toggle_menu
                title="Menu"
            >
                <img src="/logo.png" alt="Papillon" class="canvas-tab-logo" />
            </button>

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
                class="new-tab-btn"
                on:click=on_new_canvas
                title="New canvas"
            >
                "+"
            </button>

            // Slide-in settings panel
            <SettingsPanel open=menu_open />
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
        <div class="overflow-dropdown-container">
            <button
                class="overflow-dropdown-toggle"
                on:click=toggle
                title="More canvases"
            >
                "⋯"
            </button>
            {move || {
                if open.get() {
                    let canvas_list = canvases.clone();
                    Some(view! {
                        <div class="overflow-dropdown-menu">
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
                                            class="overflow-dropdown-item"
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

/// Clean settings panel with theme toggle and All Settings link.
#[component]
fn SettingsPanel(open: RwSignal<bool>) -> impl IntoView {
    let close_menu = move |_: leptos::ev::MouseEvent| {
        open.set(false);
    };

    view! {
        // Backdrop — click to close
        <div
            class=move || if open.get() { "slide-panel-backdrop open" } else { "slide-panel-backdrop" }
            on:click=close_menu
        />

        // Slide-in panel
        <div class=move || if open.get() { "slide-panel open" } else { "slide-panel" }>
            <div class="panel-body">
                // ── Settings ──
                <div class="panel-section-label">"Settings"</div>
                <ThemeToggleRow />
                {
                    let show_settings = expect_context::<RwSignal<bool>>();
                    view! {
                        <button
                            class="panel-nav-item"
                            on:click=move |_| {
                                open.set(false);
                                show_settings.set(true);
                            }
                        >
                            <span class="panel-nav-icon"><IconGear /></span>
                            "All Settings"
                        </button>
                    }
                }
            </div>
        </div>
    }
}

/// Inline Dark / Light / Auto theme toggle row.
/// Reads/writes data-theme on <html> and persists to localStorage.
#[component]
fn ThemeToggleRow() -> impl IntoView {
    let theme = RwSignal::new(
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s: web_sys::Storage| s.get_item("papillon_theme").ok().flatten())
            .unwrap_or_else(|| "dark".to_string()),
    );

    let set_theme = move |t: &'static str| {
        theme.set(t.to_string());
        if let Some(win) = web_sys::window() {
            if let Some(doc) = win.document() {
                let _ = doc.document_element()
                    .map(|el| el.set_attribute("data-theme", t));
            }
            if let Ok(Some(storage)) = win.local_storage() {
                let _ = storage.set_item("papillon_theme", t);
            }
        }
    };

    view! {
        <div class="panel-theme-row">
            <span class="panel-nav-icon">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                     stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <circle cx="12" cy="12" r="4"/>
                    <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41
                             M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
                </svg>
            </span>
            <span>"Theme"</span>
            <div class="panel-theme-pills">
                <button
                    class=move || if theme.get() == "light" { "panel-theme-pill active" } else { "panel-theme-pill" }
                    on:click=move |_| set_theme("light")
                >"Light"</button>
                <button
                    class=move || if theme.get() == "dark" { "panel-theme-pill active" } else { "panel-theme-pill" }
                    on:click=move |_| set_theme("dark")
                >"Dark"</button>
                <button
                    class=move || if theme.get() == "auto" { "panel-theme-pill active" } else { "panel-theme-pill" }
                    on:click=move |_| set_theme("auto")
                >"Auto"</button>
            </div>
        </div>
    }
}

#[component]
fn IconGear() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06
                     a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09
                     A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83
                     l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09
                     A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83
                     l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09
                     a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83
                     l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09
                     a1.65 1.65 0 0 0-1.51 1z"/>
        </svg>
    }
}
