use leptos::prelude::*;
use leptos::{ev, html};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::components::canvas_aside::AsideOpen;
use crate::state::canvas::CanvasState;
use crate::state::catalog::CatalogState;

/// Inline prompt input for canvas - similar to the old topbar prompt but lives within the canvas.
#[component]
pub fn InlinePrompt() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let catalog_state = use_context::<CatalogState>();
    let aside_open = use_context::<AsideOpen>().map(|AsideOpen(open)| open);
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
        if let Some(open) = aside_open {
            open.set(true);
        }
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
        <div class="inline-prompt">
            <input
                node_ref=input_ref
                class="inline-prompt-input"
                type="text"
                placeholder="Search agents, ask a question, or enter a pap:// address\u{2026}"
                prop:value=move || input_value.get()
                on:input=move |e| {
                    input_value.set(event_target_value(&e));
                    selected_idx.set(None);
                }
                on:keydown=on_keydown
                on:dragover=|e: web_sys::DragEvent| {
                    e.prevent_default();
                }
                on:drop=move |e: web_sys::DragEvent| {
                    e.prevent_default();
                    if let Some(dt) = e.data_transfer() {
                        if let Ok(text) = dt.get_data("text/plain") {
                            if text.contains("{{block:") {
                                let id_start = text.find("{{block:").map(|i| i + 8);
                                let id_end = text.find("}}");
                                if let (Some(s), Some(e_idx)) = (id_start, id_end) {
                                    if s < e_idx {
                                        let block_id = text[s..e_idx].to_string();
                                        canvas_state.insert_block_ref(block_id);
                                        return;
                                    }
                                }
                            }
                            let current = input_value.get();
                            input_value.set(format!("{}{}", current, text));
                        }
                    }
                }
            />
            <Show when=move || show_pap_suggestions.get()>
                <div class="inline-prompt-suggestions">
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
                                        let domain = name_for_click
                                            .strip_prefix("__pap_discover__:")
                                            .unwrap_or(&name_for_click)
                                            .to_string();
                                        canvas_state.submit_prompt(
                                            format!("pap+discovery://{domain}")
                                        );
                                        if let Some(open) = aside_open {
                                            open.set(true);
                                        }
                                        input_value.set(String::new());
                                    } else {
                                        let full = format!("pap://{}", name_for_click);
                                        if name_for_click.contains('.') {
                                            canvas_state.submit_prompt(full);
                                            if let Some(open) = aside_open {
                                                open.set(true);
                                            }
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
