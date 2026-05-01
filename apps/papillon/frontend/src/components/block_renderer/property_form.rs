//! Interactive property form for Ghost blocks.
//!
//! When a Ghost block's `disclosure_preview` lists required properties, this
//! component renders form inputs so the user can supply values before mandate
//! execution.  Each property is mapped to an appropriate HTML input type based
//! on naming heuristics (email, phone, date, amount).
//!
//! Form state is stored locally in an `RwSignal<HashMap<String, String>>` and
//! also written to `CanvasState::block_form_values` on every keystroke so that
//! `render_workflow` / `approve_block` can access the values.
//!
//! Text inputs support `{{block:` prefix detection — typing that prefix shows
//! a dropdown of available block IDs from the current canvas for composition.

use leptos::prelude::*;
use std::collections::HashMap;

use crate::state::canvas::CanvasState;

/// Determine the HTML input type from a disclosure property name.
fn input_type_for_property(property: &str) -> &'static str {
    let lower = property.to_lowercase();
    if lower.contains("email") {
        "email"
    } else if lower.contains("phone") || lower.contains("tel") {
        "tel"
    } else if lower.contains("date") {
        "date"
    } else if lower.contains("amount") || lower.contains("price") {
        "number"
    } else {
        "text"
    }
}

/// Strip the `schema:` prefix from a property name for display.
fn display_label(property: &str) -> String {
    property
        .trim_start_matches("schema:")
        .to_string()
}

/// Interactive property form rendered inside Ghost blocks.
///
/// Each disclosure field gets a labelled input.  Values are persisted into
/// `CanvasState::block_form_values[block_id]` on every input event.
#[component]
pub fn PropertyForm(
    /// The disclosure property names from the Ghost block.
    disclosure_fields: Vec<String>,
    /// The owning block's ID — used as the key into `block_form_values`.
    block_id: String,
) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    // Local reactive form state — seeded empty for each field.
    let form_values: RwSignal<HashMap<String, String>> = RwSignal::new(
        disclosure_fields
            .iter()
            .map(|f| (f.clone(), String::new()))
            .collect(),
    );

    // Sync initial empty map into canvas state.
    {
        let bid = block_id.clone();
        let initial: HashMap<String, String> = disclosure_fields
            .iter()
            .map(|f| (f.clone(), String::new()))
            .collect();
        canvas_state.block_form_values.update(|m| {
            m.insert(bid, initial);
        });
    }

    view! {
        <div
            class="property-form"
            on:click=|e: leptos::ev::MouseEvent| e.stop_propagation()
        >
            {disclosure_fields
                .into_iter()
                .map(|field| {
                    let field_key = field.clone();
                    let block_id_inner = block_id.clone();
                    let input_type = input_type_for_property(&field);
                    let label = display_label(&field);
                    let is_text = input_type == "text";

                    view! {
                        <PropertyField
                            field_key=field_key
                            block_id=block_id_inner
                            input_type=input_type
                            label=label
                            is_text=is_text
                            form_values=form_values
                        />
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}

/// A single form field with optional block-reference autocomplete.
#[component]
fn PropertyField(
    field_key: String,
    block_id: String,
    input_type: &'static str,
    label: String,
    is_text: bool,
    form_values: RwSignal<HashMap<String, String>>,
) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let blocks_memo = canvas_state.current_canvas_blocks();

    // Whether the block-reference dropdown is visible.
    let show_dropdown = RwSignal::new(false);

    // Current input value derived from the form map.
    let field_key_read = field_key.clone();
    let current_value = move || {
        form_values
            .get()
            .get(&field_key_read)
            .cloned()
            .unwrap_or_default()
    };

    let field_key_input = field_key.clone();
    let block_id_input = block_id.clone();
    let on_input = move |e: leptos::ev::Event| {
        let val = event_target_value(&e);

        // Update local form state.
        form_values.update(|m| {
            m.insert(field_key_input.clone(), val.clone());
        });

        // Sync to canvas state.
        canvas_state.block_form_values.update(|m| {
            m.entry(block_id_input.clone())
                .or_default()
                .insert(field_key_input.clone(), val.clone());
        });

        // Show block-ref dropdown when the value ends with "{{block:".
        if is_text {
            show_dropdown.set(val.ends_with("{{block:"));
        }
    };

    // Use StoredValue for strings that need to be accessed inside Fn closures
    // (StoredValue is Copy, so it doesn't make closures FnOnce).
    let field_key_stored = StoredValue::new(field_key.clone());
    let block_id_stored = StoredValue::new(block_id.clone());

    view! {
        <div class="property-form-field">
            <label class="property-form-label">{label}</label>
            <div style="position: relative;">
                <input
                    class="property-form-input"
                    type=input_type
                    prop:value=current_value
                    on:input=on_input
                    placeholder=format!("Enter {}...", display_label(&field_key))
                />
                <Show when=move || is_text && show_dropdown.get()>
                    <div class="block-ref-dropdown">
                        {move || {
                            let fk = field_key_stored.get_value();
                            let bid = block_id_stored.get_value();
                            let exclude_id = block_id_stored.get_value();
                            blocks_memo
                                .get()
                                .into_iter()
                                .filter(|b| b.id != exclude_id)
                                .map(|b| {
                                    let ref_label = b
                                        .prompt_text
                                        .as_deref()
                                        .map(|t| {
                                            if t.len() > 30 {
                                                format!("{}...", &t[..30])
                                            } else {
                                                t.to_string()
                                            }
                                        })
                                        .unwrap_or_else(|| b.id.clone());
                                    (b.id, ref_label)
                                })
                                .map(|(ref_id, ref_label)| {
                                    let fk_inner = fk.clone();
                                    let bid_inner = bid.clone();
                                    let ref_id_click = ref_id.clone();
                                    view! {
                                        <div
                                            class="block-ref-option"
                                            on:click=move |_| {
                                                // Replace the trailing "{{block:" with "{{block:ID}}"
                                                form_values.update(|m| {
                                                    if let Some(val) = m.get_mut(&fk_inner) {
                                                        if let Some(prefix) = val.strip_suffix("{{block:") {
                                                            *val = format!("{}{{{{block:{}}}}}", prefix, ref_id_click);
                                                        }
                                                    }
                                                });
                                                // Sync to canvas state.
                                                let snapshot = form_values.get_untracked();
                                                canvas_state.block_form_values.update(|m| {
                                                    m.insert(bid_inner.clone(), snapshot);
                                                });
                                                show_dropdown.set(false);
                                            }
                                        >
                                            <span class="block-ref-id">{ref_id}</span>
                                            <span class="block-ref-label">{format!(" - {}", ref_label)}</span>
                                        </div>
                                    }
                                })
                                .collect::<Vec<_>>()
                        }}
                    </div>
                </Show>
            </div>
        </div>
    }
}
