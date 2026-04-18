use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock};

use crate::state::canvas::CanvasState;
use crate::state::templates::TemplatesState;

/// Side-panel listing all resolved/outcome blocks on the current canvas as
/// draggable chips.  Each chip lets the user:
///
/// - **Click** — insert `{{block:ID}}` into the topbar address bar (composing
///   the block's result as context for a new prompt).
/// - **Drag** — drag the chip onto any text input; the `text/plain` payload is
///   the `{{block:ID}}` reference string.
/// - **Reshape** — open the inline picker and choose a different template to
///   re-render the block's content without re-running the agent.
#[component]
pub fn SourcePanel() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let resolved_blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| {
                c.blocks
                    .into_iter()
                    .filter(|b| {
                        matches!(b.state, BlockState::Resolved | BlockState::Outcome { .. } | BlockState::Note { .. })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };

    view! {
        <div class="source-panel">
            <div class="source-panel-header">
                <span class="source-panel-title">"Sources"</span>
                <span class="source-count">{move || resolved_blocks().len()}</span>
            </div>
            <div class="source-chips">
                <For
                    each=resolved_blocks
                    key=|b| b.id.clone()
                    children=|block| view! { <SourceChip block=block /> }
                />
            </div>
        </div>
    }
}

/// A single chip representing one resolved block.
#[component]
fn SourceChip(block: CanvasBlock) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let templates_state = expect_context::<TemplatesState>();

    let block_id = block.id.clone();
    let block_id_for_drag = block_id.clone();
    let block_id_for_reshape = block_id.clone();

    // For Note blocks show the note title with a pencil prefix.
    // For agent blocks extract the agent name from the JSON-LD envelope.
    let is_note = matches!(&block.state, BlockState::Note { .. });
    let agent_name = if is_note {
        block.content
            .as_ref()
            .and_then(|c| c.get("title").and_then(|t| t.as_str()))
            .map(|t| format!("✏ {}", t))
            .unwrap_or_else(|| "✏ Note".to_string())
    } else {
        block
            .content
            .as_ref()
            .and_then(|c| c.get("agent").and_then(|a| a.as_str()))
            .unwrap_or_else(|| {
                if block_id.len() > 8 {
                    &block_id[..8]
                } else {
                    &block_id
                }
            })
            .to_string()
    };

    let schema_type = block
        .schema_type
        .clone()
        .unwrap_or_default()
        .trim_start_matches("schema:")
        .to_string();

    let has_schema = !schema_type.is_empty();

    // The text/plain payload dropped onto the address bar.
    let drag_ref_text = format!("{{{{block:{}}}}}", block_id_for_drag);

    let (show_reshape, set_show_reshape) = signal(false);
    let (selected_template, set_selected_template) = signal(String::new());

    let on_chip_click = {
        let block_id = block_id.clone();
        let cs = canvas_state;
        move |_| cs.insert_block_ref(block_id.clone())
    };

    // TTL badge decay class derived from mandate_expires_at (mirrors the
    // logic in BlockRenderer so styling stays consistent).
    let ttl_badge = block.mandate_expires_at.as_ref().map(|expires| {
        let now_ms = js_sys::Date::now();
        let exp_ms =
            js_sys::Date::new(&wasm_bindgen::JsValue::from_str(expires)).get_time();
        let remaining_ms = exp_ms - now_ms;
        let decay_class = if remaining_ms < 0.0 {
            "source-chip-ttl decay-readonly"
        } else if remaining_ms < 600_000.0 {
            "source-chip-ttl decay-degraded"
        } else {
            "source-chip-ttl decay-active"
        };
        decay_class
    });

    view! {
        <div
            class="source-chip"
            draggable="true"
            on:dragstart=move |e: web_sys::DragEvent| {
                if let Some(dt) = e.data_transfer() {
                    let _ = dt.set_data("text/plain", &drag_ref_text);
                }
            }
        >
            <div class="source-chip-main" on:click=on_chip_click>
                <span class="source-chip-agent">{agent_name}</span>
                {if has_schema {
                    view! { <span class="source-chip-type">{schema_type}</span> }.into_any()
                } else {
                    view! { <span></span> }.into_any()
                }}
                {ttl_badge.map(|cls| view! { <span class=cls>"●"</span> }.into_any())}
            </div>
            <button
                class="source-chip-reshape"
                title="Reshape: apply a different template to this block"
                on:click=move |e: leptos::ev::MouseEvent| {
                    e.stop_propagation();
                    set_show_reshape.update(|v| *v = !*v);
                }
            >
                "\u{27f3}"
            </button>

            // Reshape picker — visible only when the user clicks the ⟳ button.
            <Show when=move || show_reshape.get()>
                <div class="reshape-picker">
                    <select
                        on:change=move |e| {
                            set_selected_template.set(event_target_value(&e));
                        }
                    >
                        <option value="">"\u{2014} choose template \u{2014}"</option>
                        {move || {
                            templates_state
                                .all_templates()
                                .into_iter()
                                .map(|t| {
                                    let name = t.template_name.clone();
                                    let name2 = name.clone();
                                    view! {
                                        <option value={name}>{name2}</option>
                                    }
                                })
                                .collect::<Vec<_>>()
                        }}
                    </select>
                    <button
                        class="reshape-picker-apply"
                        on:click={
                            let block_id2 = block_id_for_reshape.clone();
                            let cs2 = canvas_state;
                            move |_| {
                                let tpl = selected_template.get();
                                if !tpl.is_empty() {
                                    cs2.reshape_block_template(block_id2.clone(), tpl);
                                    set_show_reshape.set(false);
                                }
                            }
                        }
                    >
                        "Apply"
                    </button>
                </div>
            </Show>
        </div>
    }
}
