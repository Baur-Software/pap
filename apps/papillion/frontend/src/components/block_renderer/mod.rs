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
    let is_resolved = matches!(block.state, BlockState::Resolved | BlockState::Outcome { .. });

    let block_class = match &block.state {
        BlockState::Ghost { .. } => "canvas-block ghost",
        BlockState::Resolving { .. } => "canvas-block resolving",
        BlockState::Resolved => "canvas-block",
        BlockState::Failed { .. } => "canvas-block failed",
        BlockState::Outcome { .. } => "canvas-block outcome",
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
                BlockState::Ghost { agent_name, action_type, disclosure_preview, returns_preview } => {
                    let agent = agent_name.clone();
                    let action = action_type.clone();
                    let disclosures = disclosure_preview.clone();
                    let returns = returns_preview.clone();
                    let disclosures_empty = disclosures.is_empty();
                    let returns_empty = returns.is_empty();
                    view! {
                        <div class="ghost-header">
                            <span class="ghost-agent">{agent}</span>
                            <span class="ghost-action">{action}</span>
                        </div>
                        <div class="ghost-scope">
                            <Show when=move || !disclosures_empty>
                                <div class="ghost-disclosure">
                                    <span class="ghost-scope-label">"Will see"</span>
                                    <div class="scope-badges">
                                        {disclosures.iter().map(|d| {
                                            let d = d.clone();
                                            view! { <span class="scope-badge disclosure">{d}</span> }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                </div>
                            </Show>
                            <Show when=move || !returns_empty>
                                <div class="ghost-returns">
                                    <span class="ghost-scope-label">"Will return"</span>
                                    <div class="scope-badges">
                                        {returns.iter().map(|r| {
                                            let r = r.clone();
                                            view! { <span class="scope-badge returns">{r}</span> }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                </div>
                            </Show>
                        </div>
                    }.into_any()
                }
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
                BlockState::Outcome { provenance_block_ids } => {
                    let prov_ids = provenance_block_ids.clone();
                    let prov_count = prov_ids.len();
                    let show_provenance = RwSignal::new(false);

                    let content_view = match (&block.schema_type, &block.content) {
                        (Some(t), Some(content)) => render_typed_content(t, content, &registry),
                        (None, Some(content)) => {
                            // Outcome blocks may not have a schema_type — render
                            // the synthesized result as a generic answer block.
                            let text = content
                                .get("result")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let text = text.to_string();
                            view! {
                                <div class="typed-answer">
                                    <p class="typed-answer-text">{text}</p>
                                </div>
                            }.into_any()
                        }
                        _ => view! { <div class="typed-generic"><span class="typed-label">"Synthesizing..."</span></div> }.into_any(),
                    };

                    view! {
                        <div class="outcome-surface">
                            <div class="block-content">{content_view}</div>
                        </div>
                        <div class="provenance-footer">
                            <button
                                class="provenance-toggle"
                                on:click=move |_| show_provenance.update(|v| *v = !*v)
                            >
                                {format!("{} agent{} contributed", prov_count, if prov_count == 1 { "" } else { "s" })}
                                <span class="provenance-chevron"
                                    class:expanded=move || show_provenance.get()
                                >">"</span>
                            </button>
                            <Show when=move || show_provenance.get()>
                                <ProvenanceLayer block_ids=prov_ids.clone() />
                            </Show>
                        </div>
                        <Show when=move || show_reprompt.get()>
                            <div class="block-reprompt">
                                <input
                                    type="text"
                                    placeholder="Reshape this outcome..."
                                    prop:value=move || reprompt_value.get()
                                    on:input=move |e| reprompt_value.set(event_target_value(&e))
                                    on:keydown=on_reprompt_keydown
                                />
                            </div>
                        </Show>
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

/// Expandable provenance layer showing the individual agent blocks that
/// contributed to an outcome block. Each entry shows the agent name,
/// action type, and a scope badge summarizing what it saw/returned.
#[component]
fn ProvenanceLayer(block_ids: Vec<String>) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let ids = block_ids.clone();

    // Look up the referenced blocks from the canvas state
    let entries = move || {
        let canvases = canvas_state.canvases.get();
        ids.iter()
            .filter_map(|id| {
                canvases
                    .iter()
                    .flat_map(|c| c.blocks.iter())
                    .find(|b| &b.id == id)
                    .cloned()
            })
            .collect::<Vec<_>>()
    };

    view! {
        <div class="provenance-layer">
            <For
                each=entries
                key=|b| b.id.clone()
                children=move |block| {
                    let agent_name = block
                        .content
                        .as_ref()
                        .and_then(|c| c.get("agent"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown agent")
                        .to_string();
                    let action = block
                        .schema_type
                        .clone()
                        .unwrap_or_else(|| "Action".into());
                    let has_receipt = block
                        .content
                        .as_ref()
                        .map(|c| c.get("receipt").is_some())
                        .unwrap_or(false);

                    view! {
                        <div class="provenance-entry">
                            <span class="provenance-agent">{agent_name}</span>
                            <span class="provenance-action">{action}</span>
                            <Show when=move || has_receipt>
                                <span class="scope-badge receipt">"co-signed"</span>
                            </Show>
                        </div>
                    }
                }
            />
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
