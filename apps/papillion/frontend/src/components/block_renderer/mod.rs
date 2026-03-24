mod declarative;
mod field_classify;
mod generic;
mod receipt;
mod registry;
mod renderer;
mod templates;

use leptos::prelude::*;
use papillion_shared::{BlockState, CanvasBlock};
use serde_json::Value;
use std::sync::Arc;

use crate::state::canvas::CanvasState;
use crate::state::templates::TemplatesState;
use registry::RendererRegistry;

/// Create and initialize the default renderer registry with shipped templates.
fn create_default_registry() -> Arc<RendererRegistry> {
    let registry = Arc::new(RendererRegistry::new());
    registry.register(Arc::new(templates::FlightTemplate));
    registry.register(Arc::new(templates::HotelTemplate));
    registry.register(Arc::new(templates::SearchTemplate));
    registry.register(Arc::new(templates::AnswerTemplate));
    registry
}

/// Render a single canvas block based on its state and JSON-LD @type.
#[component]
pub fn BlockRenderer(block: CanvasBlock) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let templates_state = expect_context::<TemplatesState>();

    let registry = create_default_registry();

    // Load user-defined templates from context
    let all_templates = templates_state.all_templates();
    if !all_templates.is_empty() {
        let _ = registry.load_from_templates(all_templates);
    }

    let block_id = StoredValue::new(block.id.clone());
    let show_reprompt = RwSignal::new(false);
    let reprompt_value = RwSignal::new(String::new());
    let is_resolved = matches!(block.state, BlockState::Resolved);

    let block_class = match &block.state {
        BlockState::Resolving { .. } => "canvas-block resolving",
        BlockState::Resolved => "canvas-block",
        BlockState::Failed { .. } => "canvas-block failed",
    };

    let on_click = move |_| {
        if is_resolved {
            show_reprompt.update(|v| *v = !*v);
        }
    };

    let on_reprompt_keydown = move |e: leptos::ev::KeyboardEvent| {
        if e.key() == "Enter" {
            let text = reprompt_value.get();
            if !text.trim().is_empty() {
                canvas_state.submit_reshape(block_id.get_value(), text);
                show_reprompt.set(false);
                reprompt_value.set(String::new());
            }
        } else if e.key() == "Escape" {
            show_reprompt.set(false);
            reprompt_value.set(String::new());
        }
    };

    let on_retry = move |_| {
        canvas_state.retry_block(block_id.get_value());
    };

    view! {
        <div class=block_class role="article" tabindex="0" on:click=on_click>
            {match &block.state {
                BlockState::Resolving { phase, phase_label } => {
                    view! {
                        <PhaseDots current_phase=*phase />
                        <div class="phase-label">{phase_label.clone()}</div>
                        <div class="block-skeleton">
                            <div class="skeleton-line"></div>
                            <div class="skeleton-line"></div>
                            <div class="skeleton-line"></div>
                        </div>
                    }.into_any()
                }
                BlockState::Resolved => {
                    let content_view = match (&block.schema_type, &block.content) {
                        (Some(t), Some(content)) => render_typed_content(t, content, &registry),
                        _ => view! { <div class="typed-generic"><span class="typed-label">"Unknown"</span></div> }.into_any(),
                    };
                    view! {
                        <div class="block-content">
                            {content_view}
                        </div>
                        <Show when=move || show_reprompt.get()>
                            <div class="block-reprompt">
                                <input
                                    type="text"
                                    placeholder="Reshape this block..."
                                    prop:value=move || reprompt_value.get()
                                    on:input=move |e| reprompt_value.set(event_target_value(&e))
                                    on:keydown=on_reprompt_keydown
                                />
                            </div>
                        </Show>
                    }.into_any()
                }
                BlockState::Failed { phase, reason } => {
                    let phase = *phase;
                    let reason = reason.clone();
                    view! {
                        <PhaseDots current_phase=phase failed=true />
                        <div class="block-failed-info">
                            <span class="block-failed-msg">
                                {format!("Failed at phase {}: {}", phase, reason)}
                            </span>
                            <button class="btn-retry" on:click=on_retry>"Retry"</button>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

/// Render 6 phase dots showing handshake progress.
#[component]
fn PhaseDots(current_phase: u8, #[prop(default = false)] failed: bool) -> impl IntoView {
    let dots = (1..=6u8)
        .map(move |i| {
            let class = if failed && i == current_phase {
                "phase-dot failed"
            } else if i < current_phase {
                "phase-dot completed"
            } else if i == current_phase {
                "phase-dot active"
            } else {
                "phase-dot"
            };
            view! { <div class=class></div> }
        })
        .collect::<Vec<_>>();

    view! {
        <div class="phase-dots" aria-live="polite" aria-label=move || format!("Handshake phase {} of 6", current_phase)>
            {dots}
        </div>
    }
}

/// Top-level dispatch: unwrap the handshake envelope, stream-parse the JSON-LD,
/// and attach receipt metadata footer.
///
/// The handshake wraps agent output as:
/// ```json
/// { "@type": "...", "agent": "...", "query": "...", "result": {payload}, "receipt": {...} }
/// ```
fn render_typed_content(
    schema_type: &str,
    content: &Value,
    registry: &Arc<RendererRegistry>,
) -> AnyView {
    // Extract the agent's actual result from the handshake envelope.
    // Fall back to the full content if there's no "result" key (direct JSON-LD).
    let payload = content.get("result").unwrap_or(content);
    let receipt_val = content.get("receipt");

    // Stream-flatten the JSON-LD tree and render all entries — no depth limit.
    let entries = generic::flatten_to_entries(schema_type, payload, registry);
    let content_view = generic::render_stream(entries, registry);

    receipt::wrap_with_receipt(content_view, receipt_val)
}
