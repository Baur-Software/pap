use leptos::prelude::*;
use leptos::{ev, html};
use leptos_router::components::A;
use leptos_router::hooks::use_location;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use papillon_shared::BlockState;

use crate::components::canvas_aside::AsideOpen;
use crate::state::canvas::{CanvasSide, CanvasState};
use crate::state::catalog::CatalogState;

#[component]
pub fn TopBar() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let menu_open = RwSignal::new(false);

    let is_back = move || canvas_state.canvas_side.get() == CanvasSide::Back;
    let toggle_side = move |_: leptos::ev::MouseEvent| {
        canvas_state.canvas_side.update(|s| {
            *s = if *s == CanvasSide::Front {
                CanvasSide::Back
            } else {
                CanvasSide::Front
            };
        });
    };

    let toggle_menu = move |_: leptos::ev::MouseEvent| {
        menu_open.update(|v| *v = !*v);
    };
    let close_menu = move |_: leptos::ev::MouseEvent| {
        menu_open.set(false);
    };

    let canvases = move || canvas_state.canvases.get();
    let active_id = move || canvas_state.current_canvas_id.get();

    view! {
        <header class="topbar app-topbar">
            <button class="topbar-brand" on:click=toggle_menu title="Menu">
                <img class="topbar-brand-icon" src="/logo.png" alt="Papillon" />
                <span class="topbar-brand-name">"Papillon"</span>
            </button>

            <div class="topbar-address">
                <TopbarPrompt />
            </div>

            <div class="topbar-end">
                {
                    let blocks = canvas_state.current_canvas_blocks();
                    let has_pending = Memo::new(move |_| {
                        blocks.get().iter().any(|b| matches!(
                            &b.state,
                            BlockState::Ghost { .. } | BlockState::AwaitingApproval { .. }
                        ))
                    });
                    let on_render = move |_: leptos::ev::MouseEvent| {
                        canvas_state.render_workflow();
                    };
                    view! {
                        <button
                            class="canvas-render-btn"
                            on:click=on_render
                            disabled=move || !has_pending.get()
                            title="Auto-approve all pending blocks and render"
                        >
                            "\u{25b6} Render"
                        </button>
                    }
                }
                <button
                    class="canvas-flip-toggle"
                    on:click=toggle_side
                >
                    {move || if is_back() { "\u{27f3} Page" } else { "\u{27f3} Workflow" }}
                </button>
                {
                    let aside = use_context::<AsideOpen>();
                    aside.map(|AsideOpen(open)| view! {
                        <button
                            class="canvas-aside-toggle"
                            on:click=move |_| open.update(|v| *v = !*v)
                            title="Toggle conversation aside"
                        >
                            {move || if open.get() { "\u{2715} Chat" } else { "\u{1f4ac} Chat" }}
                        </button>
                    })
                }
            </div>
        </header>

        // Backdrop — click to close
        <div
            class=move || if menu_open.get() { "slide-panel-backdrop open" } else { "slide-panel-backdrop" }
            on:click=close_menu
        />

        // Slide-in panel
        <div class=move || if menu_open.get() { "slide-panel open" } else { "slide-panel" }>
            <div class="panel-body">

                // ── Canvases ──
                <div class="panel-section-label">"Canvases"</div>
                <For
                    each=canvases
                    key=|c| c.id.clone()
                    children=move |canvas| {
                        let cid_switch = canvas.id.clone();
                        let cid_delete = canvas.id.clone();
                        let cid_class  = canvas.id.clone();
                        let cid_dot    = canvas.id.clone();
                        view! {
                            <div
                                class=move || if active_id().as_deref() == Some(&cid_class) {
                                    "panel-canvas-item active"
                                } else {
                                    "panel-canvas-item"
                                }
                                on:click=move |_| {
                                    canvas_state.current_canvas_id.set(Some(cid_switch.clone()));
                                    menu_open.set(false);
                                }
                            >
                                <div class=move || if active_id().as_deref() == Some(&cid_dot) {
                                    "panel-canvas-dot active"
                                } else {
                                    "panel-canvas-dot"
                                } />
                                <span class="panel-canvas-name">{canvas.name.clone()}</span>
                                <div class="panel-canvas-actions">
                                    <button
                                        class="panel-canvas-btn delete"
                                        title="Delete canvas"
                                        on:click=move |e| {
                                            e.stop_propagation();
                                            canvas_state.delete_canvas(&cid_delete);
                                        }
                                    >
                                        "\u{00d7}"
                                    </button>
                                </div>
                            </div>
                        }
                    }
                />
                <button
                    class="panel-new-canvas-btn"
                    on:click=move |_| {
                        canvas_state.new_canvas();
                        menu_open.set(false);
                    }
                >
                    <span>"+ New Canvas"</span>
                    <span class="panel-kbd">"\u{2318}K"</span>
                </button>

                <div class="panel-divider" />

                // ── Navigate ──
                <div class="panel-section-label">"Navigate"</div>
                <PanelNavItem href="/receipts" label="Receipts" close_panel=menu_open>
                    <IconHistory />
                </PanelNavItem>

                <div class="panel-divider" />

                // ── Settings ──
                <div class="panel-section-label">"Settings"</div>
                <ThemeToggleRow />
                {
                    let show_settings = expect_context::<RwSignal<bool>>();
                    view! {
                        <button
                            class="panel-nav-item"
                            on:click=move |_| {
                                menu_open.set(false);
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

/// Browser-style address bar — lives in the top chrome across all pages.
/// Accepts natural-language prompts, pap:// URIs, and https:// URLs.
/// Identical logic to the former canvas InlinePrompt, but styled as a
/// compact pill input rather than a card.
#[component]
fn TopbarPrompt() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let catalog_state = use_context::<CatalogState>();
    let input_ref = NodeRef::<html::Input>::new();
    let input_value = RwSignal::new(String::new());
    let selected_idx: RwSignal<Option<usize>> = RwSignal::new(None);

    // Live pap:// completions from the catalog, plus web-browse for domains.
    //
    // - Web domain (prefix contains '.') → single "Browse → domain" suggestion.
    //   Any external domain resolves to HttpsEndpoint and routes to Web Page Reader.
    // - Catalog name (no dot) → agent name completions from local catalog.
    let pap_suggestions = Memo::new(move |_| {
        let val = input_value.get();
        if !val.starts_with("pap://") {
            return vec![];
        }
        let prefix = val["pap://".len()..].to_lowercase();
        if prefix.is_empty() {
            return vec![];
        }
        // Web domain: show two suggestions —
        //   1. "Browse → pap://domain" (existing direct-browse path)
        //   2. "Check for PAP agents at domain" (well-known discovery)
        if prefix.contains('.') {
            return vec![
                prefix.clone(),
                format!("__pap_discover__:{prefix}"),
            ];
        }
        // Catalog agent name match.
        let entries = catalog_state
            .map(|c| c.entries.get())
            .unwrap_or_default();
        let mut names: Vec<String> = entries
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .take(8)
            .cloned()
            .collect();
        names.sort();
        names
    });

    let show_pap_suggestions = Memo::new(move |_| {
        input_value.get().starts_with("pap://") && !pap_suggestions.get().is_empty()
    });

    let submit = move || {
        let text = input_value.get();
        if text.trim().is_empty() {
            return;
        }
        canvas_state.submit_prompt(text.clone());
        input_value.set(String::new());
        selected_idx.set(None);
    };

    let on_keydown = move |e: ev::KeyboardEvent| {
        let suggestions = pap_suggestions.get_untracked();
        match e.key().as_str() {
            "Enter" => {
                if let Some(idx) = selected_idx.get_untracked() {
                    if let Some(name) = suggestions.get(idx) {
                        if name.starts_with("__pap_discover__:") {
                            // PAP discovery suggestion: submit as pap+discovery://
                            let domain = name
                                .strip_prefix("__pap_discover__:")
                                .unwrap_or(name)
                                .to_string();
                            canvas_state.submit_prompt(format!("pap+discovery://{domain}"));
                            input_value.set(String::new());
                            selected_idx.set(None);
                            return;
                        }
                        let full = format!("pap://{name}");
                        if name.contains('.') {
                            // Web domain: submit immediately.
                            canvas_state.submit_prompt(full);
                            input_value.set(String::new());
                        } else {
                            // Catalog agent: fill the address bar so the user
                            // can review / refine before submitting.
                            input_value.set(full);
                        }
                        selected_idx.set(None);
                        return;
                    }
                }
                submit();
            }
            "ArrowDown" if !suggestions.is_empty() => {
                e.prevent_default();
                let next = match selected_idx.get_untracked() {
                    None => 0,
                    Some(i) => (i + 1).min(suggestions.len() - 1),
                };
                selected_idx.set(Some(next));
            }
            "ArrowUp" if !suggestions.is_empty() => {
                e.prevent_default();
                let prev = match selected_idx.get_untracked() {
                    None | Some(0) => None,
                    Some(i) => Some(i - 1),
                };
                selected_idx.set(prev);
            }
            "Escape" => {
                selected_idx.set(None);
            }
            _ => {}
        }
    };

    // Pick up prefill text set by agent tile clicks in the canvas empty state.
    Effect::new(move || {
        if let Some(text) = canvas_state.prefill_prompt.get() {
            input_value.set(text);
            canvas_state.prefill_prompt.set(None);
        }
    });

    // Focus on mount and whenever focus_prompt is bumped (⌘K).
    Effect::new(move || {
        let _ = canvas_state.focus_prompt.get();
        let el_opt = input_ref.get();
        let cb = Closure::once(move || {
            if let Some(el) = el_opt {
                let _ = el.focus();
            }
        });
        let window = web_sys::window().unwrap();
        let _ = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(cb.as_ref().unchecked_ref(), 50);
        cb.forget();
    });

    view! {
        <div class="topbar-address-inner">
            <input
                node_ref=input_ref
                class="topbar-address-input"
                type="text"
                placeholder="Search agents, ask a question, or enter a pap:// address\u{2026}"
                prop:value=move || input_value.get()
                on:input=move |e| {
                    input_value.set(event_target_value(&e));
                    selected_idx.set(None);
                }
                on:keydown=on_keydown
                on:dragover=|e: web_sys::DragEvent| {
                    // Required to allow the subsequent drop event to fire.
                    e.prevent_default();
                }
                on:drop=move |e: web_sys::DragEvent| {
                    e.prevent_default();
                    if let Some(dt) = e.data_transfer() {
                        if let Ok(text) = dt.get_data("text/plain") {
                            if text.contains("{{block:") {
                                // Parse block ID from "{{block:ID}}" and use
                                // insert_block_ref so the prefill signal is updated
                                // reactively (same path as agent-tile clicks).
                                let id_start = text.find("{{block:").map(|i| i + 8);
                                let id_end = text.find("}}");
                                if let (Some(s), Some(e_idx)) = (id_start, id_end) {
                                    if s < e_idx {
                                        let block_id = text[s..e_idx].to_string();
                                        canvas_state.insert_block_ref(block_id);
                                        return;
                                    }
                                }
                                // Fallback: append the raw reference text to the
                                // current input value when ID parsing fails.
                                let current = input_value.get();
                                input_value.set(format!("{}{}", current, text));
                            }
                        }
                    }
                }
            />
            <Show when=move || show_pap_suggestions.get()>
                <div class="topbar-suggestions">
                    {move || pap_suggestions.get().into_iter().enumerate().map(|(i, name)| {
                        let name_for_click = name.clone();
                        let is_discovery = name.starts_with("__pap_discover__:");
                        let is_web_domain = !is_discovery && name.contains('.');

                        view! {
                            <button
                                class="palette-suggestion palette-suggestion-pap"
                                class:palette-suggestion--active=move || selected_idx.get() == Some(i)
                                class:palette-suggestion-pap-discovery=is_discovery
                                on:click=move |_| {
                                    if is_discovery {
                                        // Strip the sentinel prefix to get the bare domain.
                                        let domain = name_for_click
                                            .strip_prefix("__pap_discover__:")
                                            .unwrap_or(&name_for_click)
                                            .to_string();
                                        // Submit as a pap+discovery intent so the orchestrator
                                        // knows to check /.well-known/pap/advertisements first.
                                        canvas_state.submit_prompt(
                                            format!("pap+discovery://{domain}")
                                        );
                                        input_value.set(String::new());
                                    } else {
                                        let full = format!("pap://{}", name_for_click);
                                        if name_for_click.contains('.') {
                                            canvas_state.submit_prompt(full);
                                            input_value.set(String::new());
                                        } else {
                                            input_value.set(full);
                                        }
                                    }
                                    selected_idx.set(None);
                                    if let Some(el) = input_ref.get() {
                                        let _ = el.focus();
                                    }
                                }
                            >
                                {if is_discovery {
                                    let domain = name
                                        .strip_prefix("__pap_discover__:")
                                        .unwrap_or(&name)
                                        .to_string();
                                    view! {
                                        <span class="pap-suggestion-scheme pap-discovery-icon">"\u{1f50d} "</span>
                                        <span class="pap-suggestion-name">
                                            {format!("Check for PAP agents at {domain}")}
                                        </span>
                                    }.into_any()
                                } else if is_web_domain {
                                    view! {
                                        <span class="pap-suggestion-scheme">"Browse  "</span>
                                        <span class="pap-suggestion-name">{format!("pap://{}", name)}</span>
                                    }.into_any()
                                } else {
                                    view! {
                                        <span class="pap-suggestion-scheme">"pap://"</span>
                                        <span class="pap-suggestion-name">{name}</span>
                                    }.into_any()
                                }}
                            </button>
                        }
                    }).collect::<Vec<_>>()}
                </div>
            </Show>
        </div>
    }
}

/// A nav link row inside the slide panel. Closes the panel on click.
#[component]
fn PanelNavItem(
    href: &'static str,
    label: &'static str,
    close_panel: RwSignal<bool>,
    children: Children,
) -> impl IntoView {
    let location = use_location();
    let href_str = href;
    view! {
        <A
            href=href
            attr:class=move || {
                if location.pathname.get().starts_with(href_str) {
                    "panel-nav-item active"
                } else {
                    "panel-nav-item"
                }
            }
            on:click=move |_| close_panel.set(false)
        >
            <span class="panel-nav-icon">{children()}</span>
            {label}
        </A>
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

// ── Icons used by panel nav items ────────────────────────────

#[component]
fn IconHistory() -> impl IntoView {
    view! {
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="1 4 1 10 7 10"/>
            <path d="M3.51 15a9 9 0 1 0 .49-4.5"/>
            <polyline points="12 7 12 12 15 15"/>
        </svg>
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
