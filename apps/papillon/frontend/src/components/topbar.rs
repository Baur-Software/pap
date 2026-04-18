use leptos::prelude::*;
use leptos::{ev, html};
use leptos_router::components::A;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

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
    let close_menu = move |_| {
        menu_open.set(false);
    };

    let canvases = move || canvas_state.canvases.get();
    let active_id = move || canvas_state.current_canvas_id.get();

    view! {
        <header class="topbar app-topbar">
            // Left zone — 64px, aligns flush with the sidebar column
            <button class="topbar-brand" on:click=toggle_menu title="Canvases">
                <img class="topbar-brand-icon" src="/logo.png" alt="Papillon" />
                <span class="topbar-brand-name">"Papillon"</span>
            </button>

            // Center zone — expands to fill remaining width
            <div class="topbar-address">
                <TopbarPrompt />
            </div>

            // Right zone — workflow toggle button
            <div class="topbar-end">
                <button
                    class="canvas-flip-toggle"
                    on:click=toggle_side
                >
                    {move || if is_back() { "\u{27f3} Rendered" } else { "\u{27f3} Workflow" }}
                </button>
            </div>
        </header>

        // Canvas switcher dropdown (triggered by brand logo click)
        <Show when=move || menu_open.get()>
            <div class="menu-backdrop" on:click=close_menu></div>
            <div class="menu-dropdown">
                <div class="menu-section-label">"Canvases"</div>
                <A href="/" attr:class="menu-item menu-item-new" on:click=move |_| {
                    canvas_state.new_canvas();
                    menu_open.set(false);
                }>
                    "+ New Canvas"
                </A>
                <For
                    each=canvases
                    key=|c| c.id.clone()
                    children=move |canvas| {
                        let cid = canvas.id.clone();
                        let cid_for_class = canvas.id.clone();
                        let cid_for_delete = canvas.id.clone();
                        view! {
                            <div class="menu-item-row">
                                <A
                                    href="/"
                                    attr:class=move || {
                                        if active_id().as_deref() == Some(&cid_for_class) {
                                            "menu-item active"
                                        } else {
                                            "menu-item"
                                        }
                                    }
                                    on:click=move |_| {
                                        canvas_state.current_canvas_id.set(Some(cid.clone()));
                                        menu_open.set(false);
                                    }
                                >
                                    {canvas.name.clone()}
                                </A>
                                <button
                                    class="menu-item-delete"
                                    title="Delete canvas"
                                    on:click=move |e| {
                                        e.stop_propagation();
                                        canvas_state.delete_canvas(&cid_for_delete);
                                    }
                                >
                                    "\u{00d7}"
                                </button>
                            </div>
                        }
                    }
                />
                <div class="menu-divider"></div>
                <A href="/browse" attr:class="menu-item" on:click=close_menu>
                    "Browse Registries"
                </A>
                <A href="/settings" attr:class="menu-item" on:click=close_menu>
                    "Settings"
                </A>
            </div>
        </Show>
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
        // Web domain: show a single confirm suggestion so the user can see
        // that pressing Enter will browse the site on the canvas.
        if prefix.contains('.') {
            return vec![prefix];
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
            />
            <Show when=move || show_pap_suggestions.get()>
                <div class="topbar-suggestions">
                    {move || pap_suggestions.get().into_iter().enumerate().map(|(i, name)| {
                        let name_for_click = name.clone();
                        let is_web_domain = name.contains('.');
                        view! {
                            <button
                                class="palette-suggestion palette-suggestion-pap"
                                class:palette-suggestion--active=move || selected_idx.get() == Some(i)
                                on:click=move |_| {
                                    let full = format!("pap://{}", name_for_click);
                                    // For web domains, selecting the suggestion submits immediately
                                    // since what's typed is already the complete address.
                                    if name_for_click.contains('.') {
                                        canvas_state.submit_prompt(full);
                                        input_value.set(String::new());
                                    } else {
                                        input_value.set(full);
                                    }
                                    selected_idx.set(None);
                                    if let Some(el) = input_ref.get() {
                                        let _ = el.focus();
                                    }
                                }
                            >
                                {if is_web_domain {
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
