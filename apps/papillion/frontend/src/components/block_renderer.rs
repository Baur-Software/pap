use leptos::prelude::*;
use papillion_shared::{BlockState, CanvasBlock};
use serde_json::Value;

use crate::state::canvas::CanvasState;

/// Render a single canvas block based on its state and JSON-LD @type.
#[component]
pub fn BlockRenderer(block: CanvasBlock) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
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
                        (Some(t), Some(content)) => render_typed_content(t, content),
                        _ => view! { <div class="typed-structured"><span class="typed-structured-type">"Unknown"</span></div> }.into_any(),
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
    let dots = (1..=6u8).map(move |i| {
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
    }).collect::<Vec<_>>();

    view! {
        <div class="phase-dots" aria-live="polite" aria-label=move || format!("Handshake phase {} of 6", current_phase)>
            {dots}
        </div>
    }
}

/// Route JSON-LD content to the correct typed component renderer.
/// All values are rendered as text — never innerHTML — per security spec.
fn render_typed_content(schema_type: &str, content: &Value) -> AnyView {
    match schema_type {
        "FlightReservation" => render_flight(content),
        "LodgingReservation" => render_hotel(content),
        "SearchResultsPage" | "SearchAction" => render_search_results(content),
        _ => render_structured_data(schema_type, content),
    }
}

fn text_field(content: &Value, key: &str) -> String {
    content.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string()
}

fn render_flight(content: &Value) -> AnyView {
    let departure = text_field(content, "departureAirport");
    let arrival = text_field(content, "arrivalAirport");
    let date = text_field(content, "departureDate");
    let price = text_field(content, "totalPrice");
    let carrier = text_field(content, "airline");

    view! {
        <div class="typed-flight">
            <div class="typed-flight-route">{format!("{} \u{2192} {}", departure, arrival)}</div>
            <div class="typed-flight-date">{date}</div>
            <div class="typed-flight-price">{format!("${}", price)}</div>
            <div class="typed-flight-carrier">{carrier}</div>
        </div>
    }.into_any()
}

fn render_hotel(content: &Value) -> AnyView {
    let name = text_field(content, "name");
    let checkin = text_field(content, "checkinDate");
    let checkout = text_field(content, "checkoutDate");
    let price = text_field(content, "totalPrice");

    view! {
        <div class="typed-hotel">
            <div class="typed-hotel-name">{name}</div>
            <div class="typed-hotel-dates">{format!("{} \u{2192} {}", checkin, checkout)}</div>
            <div class="typed-hotel-price">{format!("${}", price)}</div>
        </div>
    }.into_any()
}

fn render_search_results(content: &Value) -> AnyView {
    let items = content.get("results")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let rendered = items.into_iter().map(|item| {
        let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("-").to_string();
        let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let snippet = item.get("snippet").and_then(|v| v.as_str()).unwrap_or("").to_string();
        view! {
            <div class="typed-search-item">
                <span class="typed-search-title">{title}</span>
                <span class="typed-search-url">{url}</span>
                <span class="typed-search-snippet">{snippet}</span>
            </div>
        }
    }).collect::<Vec<_>>();

    view! {
        <div class="typed-search-results">
            {rendered}
        </div>
    }.into_any()
}

/// Fallback: render any JSON-LD as key-value pairs with @type label.
fn render_structured_data(schema_type: &str, content: &Value) -> AnyView {
    let type_label = schema_type.to_string();
    let fields = content.as_object()
        .map(|obj| {
            obj.iter()
                .filter(|(k, _)| !k.starts_with('@'))
                .map(|(k, v)| {
                    let val = match v {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        _ => serde_json::to_string(v).unwrap_or_default(),
                    };
                    (k.clone(), val)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let rendered = fields.into_iter().map(|(k, v)| {
        view! {
            <div class="typed-structured-field">
                <span class="typed-structured-key">{k}</span>
                <span class="typed-structured-val">{v}</span>
            </div>
        }
    }).collect::<Vec<_>>();

    view! {
        <div class="typed-structured">
            <span class="typed-structured-type">{type_label}</span>
            {rendered}
        </div>
    }.into_any()
}
