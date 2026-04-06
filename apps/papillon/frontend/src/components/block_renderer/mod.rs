pub(crate) mod declarative;
pub(crate) mod field_classify;
mod generic;
mod receipt;
mod registry;
pub(crate) mod renderer;
pub(crate) mod schema_property;
mod templates;

use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock};
use serde_json::Value;
use std::sync::Arc;

use crate::state::canvas::CanvasState;
use crate::state::templates::TemplatesState;
use registry::RendererRegistry;

/// Create and initialize the default renderer registry with shipped templates.
fn create_default_registry() -> Arc<RendererRegistry> {
    let registry = Arc::new(RendererRegistry::new());
    // Reservations
    registry.register(Arc::new(templates::FlightTemplate));
    registry.register(Arc::new(templates::HotelTemplate));
    // Q&A
    registry.register(Arc::new(templates::SearchTemplate));
    registry.register(Arc::new(templates::AnswerTemplate));
    // Entertainment
    registry.register(Arc::new(templates::MovieTemplate));
    registry.register(Arc::new(templates::TvSeriesTemplate));
    registry.register(Arc::new(templates::VideoGameTemplate));
    registry.register(Arc::new(templates::MusicRecordingTemplate));
    registry.register(Arc::new(templates::MusicGroupTemplate));
    registry.register(Arc::new(templates::BookTemplate));
    // News & Research
    registry.register(Arc::new(templates::NewsArticleTemplate));
    registry.register(Arc::new(templates::ScholarlyArticleTemplate));
    // People & Orgs
    registry.register(Arc::new(templates::PersonTemplate));
    registry.register(Arc::new(templates::OrganizationTemplate));
    // Places & Weather
    registry.register(Arc::new(templates::WeatherForecastTemplate));
    registry.register(Arc::new(templates::GeoCoordinatesTemplate));
    // Commerce
    registry.register(Arc::new(templates::ProductTemplate));
    // Events & Sports
    registry.register(Arc::new(templates::EventTemplate));
    registry.register(Arc::new(templates::SportsEventTemplate));
    // Education
    registry.register(Arc::new(templates::CourseTemplate));
    // Health
    registry.register(Arc::new(templates::NutritionTemplate));
    // Jobs
    registry.register(Arc::new(templates::JobPostingTemplate));
    // Arts
    registry.register(Arc::new(templates::VisualArtworkTemplate));
    // Vocabulary
    registry.register(Arc::new(templates::DefinedTermTemplate));
    registry.register(Arc::new(templates::QuotationTemplate));
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
        registry.load_from_templates(all_templates);
    }

    let block_id = StoredValue::new(block.id.clone());
    let show_reprompt = RwSignal::new(false);
    let reprompt_value = RwSignal::new(String::new());
    let is_resolved = matches!(
        block.state,
        BlockState::Resolved | BlockState::Outcome { .. }
    );

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
                        (Some(t), Some(content)) => render_typed_content(t, content, &registry, block.agent_did.as_deref()),
                        _ => view! { <div class="typed-generic"><span class="typed-label">"Unknown"</span></div> }.into_any(),
                    };
                    let pref_guided = block.preference_guided;
                    view! {
                        <div class="block-content">
                            {content_view}
                        </div>
                        <Show when=move || pref_guided>
                            <div class="preference-hint" title="Agent selected from your local interaction history — no data left your device">
                                <span class="preference-hint-icon">"◈"</span>
                                <span>"Based on your preferences"</span>
                            </div>
                        </Show>
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
                        (Some(t), Some(content)) => render_typed_content(t, content, &registry, block.agent_did.as_deref()),
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
                                on:click=move |e: leptos::ev::MouseEvent| {
                                    e.stop_propagation();
                                    show_provenance.update(|v| *v = !*v);
                                }
                            >
                                <span class="provenance-chevron"
                                    class:expanded=move || show_provenance.get()
                                >"▶"</span>
                                {format!("{} agent{} contributed", prov_count, if prov_count == 1 { "" } else { "s" })}
                                <span class="provenance-privacy-badge">"Guarded"</span>
                            </button>
                            // Always rendered; CSS grid-template-rows animates open/close.
                            <div
                                class="provenance-panel-wrap"
                                class:expanded=move || show_provenance.get()
                            >
                                <ProvenanceLayer block_ids=prov_ids.clone() />
                            </div>
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
/// contributed to an outcome block. Each entry is a full ProvenancePanel
/// showing agent DID, mandate scope, actions taken, receipt hash, and
/// decay state — the trust transparency feature.
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
                    view! { <ProvenancePanel block=block /> }
                }
            />
        </div>
    }
}

/// Full provenance panel for a single contributing agent block.
/// Shows: agent name + DID, mandate scope granted, actions taken,
/// receipt hash with link to Receipts page, and mandate decay state.
#[component]
fn ProvenancePanel(block: papillon_shared::CanvasBlock) -> impl IntoView {
    let content = block.content.clone();

    // ── Extract fields from content JSON ────────────────────
    let agent_name = content
        .as_ref()
        .and_then(|c| c.get("agent"))
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown agent")
        .to_string();

    let action = content
        .as_ref()
        .and_then(|c| c.get("receipt"))
        .and_then(|r| r.get("action"))
        .and_then(|v| v.as_str())
        .or_else(|| block.schema_type.as_deref())
        .unwrap_or("Action")
        .trim_start_matches("schema:")
        .to_string();

    // Provenance section (added by the handshake layer)
    let prov = content.as_ref().and_then(|c| c.get("provenance")).cloned();

    let agent_did = prov
        .as_ref()
        .and_then(|p| p.get("agent_did"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let issuer_did = prov
        .as_ref()
        .and_then(|p| p.get("issuer_did"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let decay_state = prov
        .as_ref()
        .and_then(|p| p.get("decay_state"))
        .and_then(|v| v.as_str())
        .unwrap_or("Active")
        .to_string();

    let disclosed: Vec<String> = prov
        .as_ref()
        .and_then(|p| p.get("disclosed"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let returns: Vec<String> = prov
        .as_ref()
        .and_then(|p| p.get("returns"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Receipt section
    let receipt = content.as_ref().and_then(|c| c.get("receipt")).cloned();

    let session_id = receipt
        .as_ref()
        .and_then(|r| r.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let co_sigs = receipt
        .as_ref()
        .and_then(|r| r.get("co_signatures"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Truncate a DID for display: show first 20 + "…" + last 8 chars.
    fn truncate_did(did: &str) -> String {
        if did.len() > 32 {
            format!("{}…{}", &did[..20], &did[did.len() - 8..])
        } else {
            did.to_string()
        }
    }

    let agent_did_short = truncate_did(&agent_did);
    let issuer_did_short = truncate_did(&issuer_did);
    let session_id_short = truncate_did(&session_id);

    let is_on_device = agent_did.is_empty();
    let has_receipt = !session_id.is_empty();
    let zero_disclosure = disclosed.is_empty();
    // Precomputed booleans for Show `when=` closures — avoids moving the
    // underlying String/Vec into the condition closure when children also need them.
    let has_issuer_did = !issuer_did.is_empty();
    let has_returns_data = !returns.is_empty();

    let decay_class = match decay_state.as_str() {
        "Active" => "decay-badge decay-active",
        "Degraded" => "decay-badge decay-degraded",
        "ReadOnly" => "decay-badge decay-readonly",
        "Suspended" => "decay-badge decay-suspended",
        _ => "decay-badge decay-active",
    };

    view! {
        <div class="provenance-entry">
            // Header row: agent name + action badge
            <div class="prov-header">
                <span class="provenance-agent">{agent_name}</span>
                <span class="provenance-action">{action}</span>
                <span class=decay_class>{decay_state.clone()}</span>
            </div>

            // Agent DID row (hidden for on-device synthesizer)
            <Show when=move || !is_on_device>
                <div class="prov-did-row">
                    <span class="prov-label">"DID"</span>
                    <span class="prov-did" title=agent_did.clone()>{agent_did_short.clone()}</span>
                </div>
            </Show>

            // Issuer DID row
            <Show when=move || has_issuer_did>
                <div class="prov-did-row">
                    <span class="prov-label">"PRINCIPAL"</span>
                    <span class="prov-did" title=issuer_did.clone()>{issuer_did_short.clone()}</span>
                </div>
            </Show>

            // Mandate scope: what the agent was permitted to see
            <div class="prov-scope-row">
                <span class="prov-label">"SAW"</span>
                <div class="scope-badges">
                    {if zero_disclosure {
                        vec![view! { <span class="scope-badge zero-disclosure">"zero disclosure"</span> }.into_any()]
                    } else {
                        disclosed.iter().map(|d| {
                            let d = d.trim_start_matches("schema:").to_string();
                            view! { <span class="scope-badge disclosure">{d}</span> }.into_any()
                        }).collect::<Vec<_>>()
                    }}
                </div>
            </div>

            // What the agent returned
            <Show when=move || has_returns_data>
                <div class="prov-scope-row">
                    <span class="prov-label">"RETURNED"</span>
                    <div class="scope-badges">
                        {returns.iter().map(|r| {
                            let r = r.trim_start_matches("schema:").to_string();
                            view! { <span class="scope-badge returns">{r}</span> }
                        }).collect::<Vec<_>>()}
                    </div>
                </div>
            </Show>

            // On-device synthesis note
            <Show when=move || is_on_device>
                <div class="prov-scope-row">
                    <span class="prov-label">"LOCAL"</span>
                    <span class="prov-ondevice">"Composed on-device — never left this machine"</span>
                </div>
            </Show>

            // Receipt section with link to Receipts page
            <Show when=move || has_receipt>
                <div class="prov-receipt-row">
                    <span class="prov-label">"RECEIPT"</span>
                    <span class="scope-badge receipt">
                        {format!("{} co-sig{}", co_sigs, if co_sigs == 1 { "" } else { "s" })}
                    </span>
                    <a
                        class="prov-receipt-link"
                        href="/receipts"
                        title=session_id.clone()
                        on:click=|e: leptos::ev::MouseEvent| e.stop_propagation()
                    >
                        {session_id_short.clone()}
                        <span class="prov-receipt-arrow">" →"</span>
                    </a>
                </div>
            </Show>
        </div>
    }
}

/// Top-level dispatch: unwrap the handshake envelope, select the best renderer,
/// and attach the receipt metadata footer.
///
/// The handshake wraps agent output as:
/// ```json
/// { "@type": "...", "agent": "...", "query": "...", "result": {payload}, "receipt": {...} }
/// ```
///
/// Dispatch priority:
/// 1. Agent-scoped renderer — `(agent_did, schema_type)` key in the registry.
///    A specific agent can own its rendering entirely, independent of the
///    global schema.org vocabulary mapping.
/// 2. Type-global renderer — the shipped or user-defined template for this
///    `schema_type`. Handled inside the generic stream renderer via `template_hit`.
/// 3. Generic stream renderer — universal fallback for unregistered types.
fn render_typed_content(
    schema_type: &str,
    content: &Value,
    registry: &Arc<RendererRegistry>,
    agent_did: Option<&str>,
) -> AnyView {
    // Extract the agent's actual result from the handshake envelope.
    // Fall back to the full content if there's no "result" key (direct JSON-LD).
    let payload = content.get("result").unwrap_or(content);
    let receipt_val = content.get("receipt");

    // Agent-scoped renderer takes priority: a specific agent can fully own its
    // output rendering without touching the shared schema-type registry.
    let content_view = if let Some(renderer) = agent_did
        .and_then(|did| registry.get_for_agent(did, schema_type))
    {
        renderer.render(payload)
    } else {
        // Fall through to the generic stream renderer, which handles template
        // dispatch (shipped + user-defined) internally via the type-global tier.
        let entries = generic::flatten_to_entries(schema_type, payload, registry);
        generic::render_stream(entries, registry)
    };

    receipt::wrap_with_receipt(content_view, receipt_val)
}
