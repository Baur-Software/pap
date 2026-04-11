pub(crate) mod declarative;
pub(crate) mod field_classify;
mod generic;
mod receipt;
pub(crate) mod registry;
pub(crate) mod renderer;
pub(crate) mod schema_property;
mod templates;

use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock};
use serde_json::Value;
use std::sync::Arc;

pub use registry::RendererRegistry;

use crate::state::canvas::CanvasState;
use crate::state::renderer::RendererState;

/// Action emitted when a user modifies a setting rendered from vocabulary.
///
/// The renderer doesn't know what it's rendering — it projects
/// PropertyValueSpecification as form inputs. When the user changes a value,
/// the renderer emits this action. The consuming page (settings, agent detail)
/// routes it to the correct Tauri command.
#[derive(Debug, Clone)]
pub struct SettingsAction {
    /// Target agent DID or "papillon" for app-level settings.
    pub target: String,
    /// The `valueName` from the PropertyValueSpecification.
    pub value_name: String,
    /// The new value.
    pub new_value: Value,
}

/// Context type for the settings action callback.
/// When present, form fields are interactive. When absent, they render read-only.
#[derive(Clone)]
pub struct SettingsActionSink(pub leptos::callback::Callback<SettingsAction>);

/// Create and initialize the default renderer registry with shipped templates.
pub fn create_default_registry() -> Arc<RendererRegistry> {
    let registry = Arc::new(RendererRegistry::new());
    // Reservations
    registry.register(Arc::new(templates::FlightTemplate));
    registry.register(Arc::new(templates::HotelTemplate));
    // Q&A — SearchResultsPage/SearchAction handled by generic composite renderer
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
    let renderer_state = expect_context::<RendererState>();

    let registry = renderer_state.registry.with_value(|r| Arc::clone(r));

    let block_id = StoredValue::new(block.id.clone());
    let show_reprompt = RwSignal::new(false);
    let reprompt_value = RwSignal::new(String::new());
    let is_resolved = matches!(
        block.state,
        BlockState::Resolved | BlockState::Outcome { .. }
    );

    let block_class = match &block.state {
        BlockState::Ghost { .. } => "canvas-block ghost",
        BlockState::AwaitingApproval { .. } => "canvas-block awaiting-approval",
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
                BlockState::AwaitingApproval { plan } => {
                    let plan = plan.clone();
                    let agent_name = plan.selected_agent_name.clone();
                    let action_label = plan
                        .action
                        .strip_prefix("schema:")
                        .unwrap_or(&plan.action)
                        .to_string();
                    let disclosure_items = plan.requires_disclosure.clone();
                    let has_disclosure = !disclosure_items.is_empty();
                    let approval_id = plan.approval_request_id.clone();
                    let approval_id_reject = approval_id.clone();
                    let block_id_approve = block_id.get_value();
                    let block_id_reject = block_id.get_value();
                    let cs_approve = canvas_state;
                    let cs_reject = canvas_state;

                    // Button labels vary by disclosure risk.
                    let approve_label = if has_disclosure { "[ GRANT ACCESS ]" } else { "[ ALLOW ]" };
                    let reject_label = if has_disclosure { "[ DENY ]" } else { "[ DECLINE ]" };

                    // TTL from the plan (sourced from orchestrator config at plan-build time).
                    let ttl_hours = plan.ttl_hours;

                    // Skeleton preview: minimal JSON-LD for the first returns type.
                    let first_returns_type = plan
                        .returns
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "schema:Thing".to_string());
                    let skeleton_json = serde_json::json!({
                        "@type": first_returns_type,
                        "name": "\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}",
                        "description": "\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}\u{2593}"
                    });
                    let skeleton_type = plan
                        .returns
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "schema:Thing".to_string());
                    // Schema type label shown above skeleton preview (strip "schema:" prefix, uppercase).
                    let skeleton_type_label = skeleton_type
                        .strip_prefix("schema:")
                        .unwrap_or(&skeleton_type)
                        .to_uppercase();
                    let skeleton_entries =
                        generic::flatten_to_entries(&skeleton_type, &skeleton_json, &registry);
                    let skeleton_view = generic::render_stream(skeleton_entries, &registry);

                    view! {
                        <div class="awaiting-approval-header">
                            <span class="approval-header-label">"AGENT REQUEST"</span>
                            <span class="approval-agent-name">{agent_name}</span>
                            <span class="approval-action-sep">"·"</span>
                            <span class="approval-action-label">{action_label}</span>
                        </div>

                        <div class="awaiting-approval-section-label">"WILL RETURN"</div>
                        <div class="approval-schema-type">{skeleton_type_label}</div>
                        <div class="awaiting-approval-skeleton-wrap">
                            {skeleton_view}
                        </div>

                        <Show when=move || has_disclosure>
                            <div class="awaiting-approval-section-label">"WILL NEED FROM YOU"</div>
                            <div class="awaiting-approval-disclosure">
                                {disclosure_items.iter().map(|item| {
                                    let label = item
                                        .trim_start_matches("schema:")
                                        .to_string();
                                    view! {
                                        <span class="scope-badge disclosure">{label}</span>
                                    }
                                }).collect::<Vec<_>>()}
                            </div>
                        </Show>

                        <div class="awaiting-approval-mandate-note">
                            {format!("DATA VALID  \u{007e}{}h  \u{00b7}  refresh any time", ttl_hours)}
                        </div>
                        <div class="awaiting-approval-mandate-note">
                            "AGENT ACCESS EXPIRES  with this mandate"
                        </div>

                        <div class="awaiting-approval-actions">
                            <button
                                class="hitl-reject-btn"
                                on:click=move |e: leptos::ev::MouseEvent| {
                                    e.stop_propagation();
                                    cs_reject.reject_block(
                                        block_id_reject.clone(),
                                        approval_id_reject.clone(),
                                    );
                                }
                            >
                                {reject_label}
                            </button>
                            <button
                                class="hitl-authorize-btn"
                                on:click=move |e: leptos::ev::MouseEvent| {
                                    e.stop_propagation();
                                    cs_approve.approve_block(
                                        block_id_approve.clone(),
                                        approval_id.clone(),
                                    );
                                }
                            >
                                {approve_label}
                            </button>
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

                    // Zero-disclosure: detected when provenance.disclosed[] is empty.
                    // The provenance object is embedded by the handshake inside the
                    // content envelope when the agent returns its co-signed receipt.
                    let is_zero_disclosure = block
                        .content
                        .as_ref()
                        .and_then(|c| c.get("provenance"))
                        .and_then(|p| p.get("disclosed"))
                        .and_then(|d| d.as_array())
                        .map(|a| a.is_empty())
                        .unwrap_or(false);

                    // TTL expiry badge: compute remaining time from mandate_expires_at.
                    // Decay: active (teal) → degraded/gold (< 10 min) → readonly/blue (expired).
                    let ttl_display: Option<(String, &'static str)> = block
                        .mandate_expires_at
                        .as_ref()
                        .map(|expires| {
                            let now_ms = js_sys::Date::now();
                            let exp_ms = js_sys::Date::new(&wasm_bindgen::JsValue::from_str(expires)).get_time();
                            let remaining_ms = exp_ms - now_ms;
                            let decay_class = if remaining_ms < 0.0 {
                                "readonly"
                            } else if remaining_ms < 600_000.0 {
                                "degraded"
                            } else {
                                "active"
                            };
                            let remaining_hours = (remaining_ms / 3_600_000.0).ceil() as i64;
                            let label = if remaining_ms < 0.0 {
                                "expired".to_string()
                            } else {
                                format!("valid \u{007e}{}h", remaining_hours.max(1))
                            };
                            (label, decay_class)
                        });
                    let has_ttl = ttl_display.is_some();
                    let ttl_label = ttl_display.as_ref().map(|(l, _)| l.clone()).unwrap_or_default();
                    let ttl_decay_class = ttl_display.as_ref().map(|(_, c)| *c).unwrap_or("active");
                    let ttl_full_class = format!("mandate-ttl {}", ttl_decay_class);

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
                        <Show when=move || is_zero_disclosure>
                            <div class="block-zero-disclosure">
                                <span class="scope-badge zero-disclosure">"zero disclosure"</span>
                                <span class="block-zd-note">"no data left this device"</span>
                            </div>
                        </Show>
                        <Show when=move || has_ttl>
                            <div class={ttl_full_class.clone()}>
                                <span>{ttl_label.clone()}</span>
                                <button
                                    class="mandate-ttl-refresh"
                                    title="Refresh this block in-place"
                                    on:click=move |e: leptos::ev::MouseEvent| {
                                        e.stop_propagation();
                                        canvas_state.retry_block(block_id.get_value());
                                    }
                                >"↺"</button>
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
pub(crate) fn render_typed_content(
    schema_type: &str,
    content: &Value,
    registry: &Arc<RendererRegistry>,
    agent_did: Option<&str>,
) -> AnyView {
    // Detect the handshake envelope by the presence of its sentinel keys
    // ("receipt" or "provenance").  When detected, extract "result" to get the
    // actual agent output.  Fall back to the full content when the block was
    // stored as direct JSON-LD (e.g. from federation or legacy blocks that did
    // not go through the standard 6-phase handshake).
    //
    // Using sentinels rather than unconditionally calling `.get("result")` is
    // important because some legitimate schema.org types (e.g. LearningResource,
    // SoftwareApplication) also carry a `"result"` property — we must not strip
    // those as if they were envelope wrappers.
    let is_envelope =
        content.get("receipt").is_some() || content.get("provenance").is_some();
    let payload = if is_envelope {
        content.get("result").unwrap_or(content)
    } else {
        content
    };
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
