mod block_controls;
pub(crate) mod dataset_template;
pub(crate) mod declarative;
pub(crate) mod field_classify;
mod generic;
pub(crate) mod property_form;
mod receipt;
pub(crate) mod registry;
pub(crate) mod renderer;
pub(crate) mod schema_property;
mod templates;

use leptos::prelude::*;
use papillon_shared::{segment_with_citations, BlockState, TextSegment};
use serde_json::Value;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

pub use registry::RendererRegistry;

use crate::state::canvas::{CanvasSide, CanvasState};
use crate::state::renderer::RendererState;
use block_controls::BlockControls;
use property_form::PropertyForm;

/// Per-block reactive UI context provided by [`BlockRenderer`].
/// Consume via `expect_context::<BlockContext>()` in any descendant component.
/// Carries all per-block reactive state so descendants never need block-ID props.
#[derive(Clone, Copy)]
pub struct BlockContext {
    /// Stable block ID — never changes after creation.
    pub id: StoredValue<String>,
    /// Whether this block is viewport-expanded.
    pub expanded: RwSignal<bool>,
    /// Whether the inline reprompt form is visible.
    pub show_reprompt: RwSignal<bool>,
    /// Current reprompt input value.
    pub reprompt_value: RwSignal<String>,
}

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
    // Web
    registry.register(Arc::new(templates::WebPageTemplate));
    // ML / Datasets
    registry.register(Arc::new(dataset_template::DatasetSearchTemplate));
    registry
}

/// Render a single canvas block based on its state and JSON-LD @type.
///
/// Accepts a `block_id` string and subscribes to that block's state via a
/// [`Memo`] — so only updates to *this* block cause a re-render.  Sibling
/// block phase ticks no longer invalidate this component.
///
/// The `BlockContext` signals (`expanded`, `show_reprompt`, `reprompt_value`)
/// are initialised once from the block's data at mount time and survive
/// subsequent phase updates without being reset.
#[component]
pub fn BlockRenderer(block_id: String) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let renderer_state = expect_context::<RendererState>();

    let registry = renderer_state.registry.with_value(|r| Arc::clone(r));

    // Stable memo: only re-fires when this block's data actually changes.
    let block_memo = canvas_state.block_signal(block_id.clone());

    // Initialise local per-block signals from the first (mount-time) block value.
    // These are intentionally NOT reactive — they hold user interaction state that
    // must survive block phase updates.
    let initial_auto_expand = block_memo.get_untracked()
        .map(|b| b.auto_expand)
        .unwrap_or(false);

    let block_ctx = BlockContext {
        id: StoredValue::new(block_id.clone()),
        expanded: RwSignal::new(initial_auto_expand),
        show_reprompt: RwSignal::new(false),
        reprompt_value: RwSignal::new(String::new()),
    };
    provide_context(block_ctx);

    // When canvas_state signals that this block should expand, set expanded=true
    // and clear the signal so no other block picks it up.
    {
        let this_block_id = block_id.clone();
        Effect::new(move |_| {
            if let Some(ref requested) = canvas_state.requested_expansion.get() {
                if *requested == this_block_id {
                    block_ctx.expanded.set(true);
                    canvas_state.requested_expansion.set(None);
                }
            }
        });
    }

    // Which face is currently visible — used to show/hide protocol metadata.
    let canvas_side = canvas_state.canvas_side;
    let on_back = move || canvas_side.get() == CanvasSide::Back;

    let on_reprompt_keydown = move |e: leptos::ev::KeyboardEvent| {
        if e.key() == "Enter" {
            let text = block_ctx.reprompt_value.get();
            if !text.trim().is_empty() {
                canvas_state.submit_reshape(block_ctx.id.get_value(), text);
                block_ctx.show_reprompt.set(false);
                block_ctx.reprompt_value.set(String::new());
            }
        } else if e.key() == "Escape" {
            block_ctx.show_reprompt.set(false);
            block_ctx.reprompt_value.set(String::new());
        }
    };

    let on_retry = move |_| {
        canvas_state.retry_block(block_ctx.id.get_value());
    };

    // The outer div class and all inner content are driven by the reactive memo.
    // When block_memo re-fires (because updated_at or state changed), only this
    // block's subtree is re-evaluated — not the entire canvas.
    view! {
        {move || {
            let block = match block_memo.get() {
                Some(b) => b,
                None => return view! { <div class="canvas-block canvas-block--missing" /> }.into_any(),
            };

            // Guide blocks are not user-resolvable — they are system meta-blocks.
            let is_resolved = matches!(
                block.state,
                BlockState::Resolved | BlockState::Outcome { .. }
            );

            // Browse-mode expansion: browse blocks fill the canvas viewport by default.
            let is_browse = block.auto_expand;
            let browse_url = block.prompt_text.clone().unwrap_or_default();

            let block_class = match &block.state {
                BlockState::Ghost { .. } => "canvas-block ghost",
                BlockState::AwaitingApproval { .. } => "canvas-block awaiting-approval",
                BlockState::Resolving { .. } => "canvas-block resolving",
                BlockState::Resolved => "canvas-block",
                BlockState::Failed { .. } => "canvas-block failed",
                BlockState::Outcome { .. } => "canvas-block outcome",
                BlockState::Guide { .. } => "canvas-block guide-block",
                BlockState::Note { .. } => "canvas-block note-block",
            };

            let prompt_text_init = block.prompt_text.clone().unwrap_or_default();

            let on_click = move |_| {
                if is_resolved {
                    let was_shown = block_ctx.show_reprompt.get_untracked();
                    if !was_shown {
                        block_ctx.reprompt_value.set(prompt_text_init.clone());
                    }
                    block_ctx.show_reprompt.set(!was_shown);
                }
            };

            let block_class_owned = block_class.to_string();
            let block_id_for_class = block.id.clone();
            let block_id_for_focus = block.id.clone();
            let block_id_for_blur = block.id.clone();
            view! {
        <div
            class=move || {
                let mut cls = block_class_owned.clone();
                if is_resolved && block_ctx.expanded.get() {
                    cls.push_str(" canvas-block--expanded");
                }
                if canvas_state.pinned_blocks.get().contains(&block_id_for_class) {
                    cls.push_str(" canvas-block--pinned");
                }
                if canvas_state.archived_blocks.get().contains(&block_id_for_class) {
                    cls.push_str(" canvas-block--archived");
                }
                cls
            }
            role="article"
            tabindex="0"
            on:click=on_click
            on:focus=move |_| {
                canvas_state.focused_block_id.set(Some(block_id_for_focus.clone()));
            }
            on:blur=move |_| {
                // Only clear if this block is still the focused one (avoids race
                // with another block's focus event that fires before this blur).
                if canvas_state.focused_block_id.get_untracked().as_deref() == Some(&block_id_for_blur) {
                    canvas_state.focused_block_id.set(None);
                }
            }
        >
            // Block controls toolbar — appears on hover for resolved/outcome blocks.
            <Show when=move || is_resolved>
                <BlockControls />
            </Show>
            // Expand / collapse toggle — appears on hover for resolved blocks.
            // Hidden when block is pinned (CSS handles via .canvas-block--pinned .block-expand-btn).
            <Show when=move || is_resolved>
                <button
                    class="block-expand-btn"
                    on:click=move |e: leptos::ev::MouseEvent| {
                        e.stop_propagation();
                        block_ctx.expanded.update(|v| *v = !*v);
                    }
                    title=move || if block_ctx.expanded.get() { "Collapse" } else { "Expand" }
                >
                    {move || if block_ctx.expanded.get() { "⊡" } else { "⊞" }}
                </button>
            </Show>
            {match &block.state {
                BlockState::Ghost { agent_name, action_type, disclosure_preview, returns_preview } => {
                    let agent = agent_name.clone();
                    let action = action_type.clone();
                    let disclosures = disclosure_preview.clone();
                    let disclosures_for_form = disclosure_preview.clone();
                    let returns = returns_preview.clone();
                    let disclosures_empty = disclosures.is_empty();
                    let disclosures_form_empty = disclosures_for_form.is_empty();
                    let returns_empty = returns.is_empty();
                    view! {
                        <div class="ghost-header">
                            <span class="ghost-agent">{agent}</span>
                            <span class="ghost-action">{action}</span>
                        </div>
                        <div class="ghost-scope">
                            <Show when=move || !disclosures_empty>
                                <div class="ghost-disclosure">
                                    <span class="ghost-scope-label">"Needs from you"</span>
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
                                    <span class="ghost-scope-label">"You'll get"</span>
                                    <div class="scope-badges">
                                        {returns.iter().map(|r| {
                                            let r = r.clone();
                                            view! { <span class="scope-badge returns">{r}</span> }
                                        }).collect::<Vec<_>>()}
                                    </div>
                                </div>
                            </Show>
                        </div>
                        <Show when=move || !disclosures_form_empty>
                            <PropertyForm
                                disclosure_fields=disclosures_for_form.clone()
                                block_id=block_ctx.id.get_value()
                            />
                        </Show>
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
                    let block_id_approve = block_ctx.id.get_value();
                    let block_id_reject = block_ctx.id.get_value();
                    let cs_approve = canvas_state;
                    let cs_reject = canvas_state;

                    let approve_label = if has_disclosure { "Allow" } else { "Allow" };
                    let reject_label = if has_disclosure { "Decline" } else { "Decline" };

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
                            <span class="approval-agent-name">{agent_name}</span>
                            <span class="approval-action-sep">"wants to"</span>
                            <span class="approval-action-label">{action_label}</span>
                        </div>

                        <div class="awaiting-approval-section-label">"You'll get"</div>
                        <div class="approval-schema-type">{skeleton_type_label}</div>
                        <div class="awaiting-approval-skeleton-wrap">
                            {skeleton_view}
                        </div>

                        <Show when=move || has_disclosure>
                            <div class="awaiting-approval-section-label">"Needs from you"</div>
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
                            {format!("Access lasts \u{007e}{}h \u{00b7} renew any time", ttl_hours)}
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
                    // Check for a client-side template override set via `reshape_block_template`.
                    // When present it takes priority over the block's persisted schema_type,
                    // letting the user re-render content through a different template without
                    // re-executing the agent handshake.
                    let effective_schema_type: Option<String> = {
                        let overrides = canvas_state.block_template_overrides.get();
                        overrides
                            .get(&block.id)
                            .cloned()
                            .or_else(|| block.schema_type.clone())
                    };
                    let content_view = match (&effective_schema_type, &block.content) {
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
                    let ttl_label = StoredValue::new(ttl_display.as_ref().map(|(l, _)| l.clone()).unwrap_or_default());
                    let ttl_decay_class = ttl_display.as_ref().map(|(_, c)| *c).unwrap_or("active");
                    let ttl_full_class = StoredValue::new(format!("mandate-ttl {}", ttl_decay_class));

                    // Prompt text shown above block content as a query label.
                    let prompt_label = block.prompt_text.clone();
                    let has_prompt_label = prompt_label.is_some();

                    view! {
                        // In-block URL bar: only for browse blocks when expanded.
                        <Show when=move || is_browse && block_ctx.expanded.get()>
                            <BrowseBar current_url=browse_url.clone() />
                        </Show>
                        // Query label — shown above content on both faces.
                        <Show when=move || has_prompt_label>
                            <div class="block-query-label">
                                {prompt_label.clone().unwrap_or_default()}
                            </div>
                        </Show>
                        <div class="block-content">
                            {content_view}
                        </div>
                        // Protocol metadata — only visible on the back face.
                        <Show when=on_back>
                            <Show when=move || pref_guided>
                                <div class="preference-hint" title="Agent selected from your local interaction history — no data left your device">
                                    <span class="preference-hint-icon">"◈"</span>
                                    <span>"Based on your preferences"</span>
                                </div>
                            </Show>
                            <Show when=move || is_zero_disclosure>
                                <div class="block-zero-disclosure">
                                    <span class="scope-badge zero-disclosure">"no data shared"</span>
                                </div>
                            </Show>
                            <Show when=move || has_ttl>
                                <div class=move || ttl_full_class.get_value()>
                                    <span>{move || ttl_label.get_value()}</span>
                                    <button
                                        class="mandate-ttl-refresh"
                                        title="Refresh this block in-place"
                                        on:click=move |e: leptos::ev::MouseEvent| {
                                            e.stop_propagation();
                                            canvas_state.retry_block(block_ctx.id.get_value());
                                        }
                                    >"↺"</button>
                                </div>
                            </Show>
                        </Show>
                        <Show when=move || block_ctx.show_reprompt.get()>
                            <div class="block-reprompt">
                                <input
                                    type="text"
                                    placeholder="Reshape this block..."
                                    prop:value=move || block_ctx.reprompt_value.get()
                                    on:input=move |e| block_ctx.reprompt_value.set(event_target_value(&e))
                                    on:keydown=on_reprompt_keydown
                                />
                            </div>
                        </Show>
                    }.into_any()
                }
                BlockState::Failed { phase, reason } => {
                    let phase = *phase;
                    let reason = reason.clone();
                    let dismiss_block_id = block_ctx.id.get_value();
                    let on_dismiss = move |_| {
                        canvas_state.delete_block(&dismiss_block_id);
                    };
                    view! {
                        <PhaseDots current_phase=phase failed=true />
                        <div class="block-failed-info">
                            <span class="block-failed-msg">
                                {reason.clone()}
                            </span>
                            <div class="block-failed-actions">
                                <button class="btn-retry" on:click=on_retry>"Retry"</button>
                                <button class="btn-dismiss" on:click=on_dismiss title="Dismiss">" \u{00d7} Dismiss"</button>
                            </div>
                        </div>
                    }.into_any()
                }
                BlockState::Guide { summary, suggestions } => {
                    let summary_text = summary.clone();
                    let suggestions_clone = suggestions.clone();
                    let canvas_state_guide = canvas_state;
                    view! {
                        <div class="guide-header">
                            <span class="guide-icon">"✦"</span>
                            <p class="guide-summary">{summary_text}</p>
                        </div>
                        <div class="guide-suggestions">
                            {suggestions_clone.into_iter().map(|s| {
                                let cs = canvas_state_guide;
                                let pt = s.prompt_template.clone();
                                let pid = s.saved_pipeline_id.clone();
                                let label_btn = s.label.clone();
                                view! {
                                    <button
                                        class="guide-suggestion-pill"
                                        on:click=move |_| {
                                            if let Some(ref pipeline_id) = pid {
                                                // Run the saved pipeline directly, emitting block
                                                // events to the current canvas so the front face
                                                // shows live progress.
                                                let canvas_id = cs.current_canvas_id.get_untracked();
                                                let pid_clone = pipeline_id.clone();
                                                let query_clone = pt.clone();
                                                cs.canvas_side.set(CanvasSide::Front);
                                                spawn_local(async move {
                                                    #[derive(serde::Serialize)]
                                                    #[serde(rename_all = "camelCase")]
                                                    struct RunArgs {
                                                        pipeline_id: String,
                                                        initial_query: String,
                                                        canvas_id: Option<String>,
                                                    }
                                                    let args = RunArgs {
                                                        pipeline_id: pid_clone,
                                                        initial_query: query_clone,
                                                        canvas_id,
                                                    };
                                                    let _ = crate::bridge::invoke::<_, serde_json::Value>(
                                                        "run_saved_pipeline",
                                                        &args,
                                                    )
                                                    .await;
                                                });
                                            } else {
                                                cs.prefill_prompt.set(Some(pt.clone()));
                                                cs.focus_prompt.update(|n| *n += 1);
                                            }
                                        }
                                    >{label_btn}</button>
                                }
                            }).collect::<Vec<_>>()}
                        </div>
                    }.into_any()
                }
                BlockState::Note { title, content, .. } => {
                    let (is_editing, set_editing) = signal(false);
                    let (edit_title, set_edit_title) = signal(title.clone());
                    let (edit_content, set_edit_content) = signal(content.clone());
                    let block_id_note = block.id.clone();
                    let canvas_id_note = canvas_state.current_canvas_id.get_untracked().unwrap_or_default();

                    view! {
                        <div class="note-header">
                            <span class="note-icon">"✏"</span>
                            <Show
                                when=move || !is_editing.get()
                                fallback=move || view! {
                                    <input
                                        class="note-title-input"
                                        prop:value=edit_title
                                        on:input=move |e| set_edit_title.set(event_target_value(&e))
                                    />
                                }.into_any()
                            >
                                <span class="note-title">{edit_title}</span>
                            </Show>
                            <div class="note-actions">
                                <Show when=move || !is_editing.get()>
                                    <button class="note-edit-btn"
                                        on:click=move |_| set_editing.set(true)>
                                        "Edit"
                                    </button>
                                </Show>
                                <Show when=move || is_editing.get()>
                                    <button class="note-save-btn" on:click={
                                        let bid = block_id_note.clone();
                                        let cid = canvas_id_note.clone();
                                        move |_| {
                                            let t = edit_title.get_untracked();
                                            let c = edit_content.get_untracked();
                                            let bid2 = bid.clone();
                                            let cid2 = cid.clone();
                                            spawn_local(async move {
                                                #[derive(serde::Serialize)]
                                                #[serde(rename_all = "camelCase")]
                                                struct NoteArgs { canvas_id: String, block_id: String, title: String, content: String }
                                                let _ = crate::bridge::invoke::<_, serde_json::Value>(
                                                    "canvas_update_note",
                                                    &NoteArgs { canvas_id: cid2, block_id: bid2, title: t, content: c },
                                                ).await;
                                            });
                                            set_editing.set(false);
                                        }
                                    }>"Save"</button>
                                    <button class="note-cancel-btn"
                                        on:click=move |_| set_editing.set(false)>
                                        "Cancel"
                                    </button>
                                </Show>
                            </div>
                        </div>
                        <div class="note-body">
                            <Show
                                when=move || is_editing.get()
                                fallback=move || {
                                    let lines = edit_content.get();
                                    view! {
                                        <div class="note-content-view">
                                            {lines.lines()
                                                .map(|l| view! { <p>{l.to_string()}</p> })
                                                .collect::<Vec<_>>()}
                                        </div>
                                    }.into_any()
                                }
                            >
                                <textarea
                                    class="note-content-input"
                                    rows="6"
                                    prop:value=edit_content
                                    on:input=move |e| set_edit_content.set(event_target_value(&e))
                                />
                            </Show>
                        </div>
                    }.into_any()
                }
                BlockState::Outcome { provenance_block_ids } => {
                    let prov_ids = provenance_block_ids.clone();
                    let prov_count = prov_ids.len();
                    let show_provenance = RwSignal::new(false);

                    // Same override lookup as the Resolved path.
                    let effective_schema_type_outcome: Option<String> = {
                        let overrides = canvas_state.block_template_overrides.get();
                        overrides
                            .get(&block.id)
                            .cloned()
                            .or_else(|| block.schema_type.clone())
                    };

                    let content_view = match (&effective_schema_type_outcome, &block.content) {
                        (Some(t), Some(content)) => render_typed_content(t, content, &registry, block.agent_did.as_deref()),
                        (None, Some(content)) => {
                            // Outcome blocks may not have a schema_type — render
                            // the synthesized result as a generic answer block.
                            // When the content has a "result" string, parse inline
                            // citations and render them as clickable [N] superscripts
                            // that expand the corresponding provenance block.
                            if let Some(text) = content.get("result").and_then(|v| v.as_str()) {
                                let segments = segment_with_citations(text);
                                let prov_ids_for_seg = prov_ids.clone();
                                let cs_for_seg = canvas_state;
                                let nodes = segments
                                    .into_iter()
                                    .map(move |seg| {
                                        match seg {
                                            TextSegment::Plain(t) => {
                                                view! { <span>{t}</span> }.into_any()
                                            }
                                            TextSegment::Citation { index } => {
                                                let bid = prov_ids_for_seg
                                                    .get(index.saturating_sub(1))
                                                    .cloned();
                                                let label = format!("[{}]", index);
                                                view! {
                                                    <button
                                                        class="inline-citation"
                                                        title=format!("Source {}", index)
                                                        on:click=move |_| {
                                                            if let Some(ref b) = bid {
                                                                cs_for_seg.expand_block(b.clone());
                                                            }
                                                        }
                                                    >{label}</button>
                                                }.into_any()
                                            }
                                        }
                                    })
                                    .collect::<Vec<_>>();
                                view! {
                                    <div class="typed-answer">
                                        <p class="typed-answer-text">{nodes}</p>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="typed-generic">
                                        <span class="typed-label">"Synthesizing..."</span>
                                    </div>
                                }.into_any()
                            }
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
                        <Show when=move || block_ctx.show_reprompt.get()>
                            <div class="block-reprompt">
                                <input
                                    type="text"
                                    placeholder="Reshape this outcome..."
                                    prop:value=move || block_ctx.reprompt_value.get()
                                    on:input=move |e| block_ctx.reprompt_value.set(event_target_value(&e))
                                    on:keydown=on_reprompt_keydown
                                />
                            </div>
                        </Show>
                    }.into_any()
                }
            }}
        </div>
        }.into_any()
    }}
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
        <div class="phase-dots" aria-live="polite" aria-label=move || format!("Connecting, step {} of 6", current_phase)>
            {dots}
        </div>
    }
}

/// URL bar shown inside a browse block when it is expanded.
///
/// Pre-fills with the current block URL.  Pressing Enter submits the new URL
/// as `submit_agent_link` (which spawns a linked browse block with
/// `auto_expand=true`), then collapses the current block so the new one fills
/// the viewport.  Pressing Escape collapses without navigating.
#[component]
fn BrowseBar(
    /// Current page URL — used to pre-fill the input.
    current_url: String,
) -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let block_ctx = expect_context::<BlockContext>();
    let url_input = RwSignal::new(current_url);

    let on_keydown = move |e: leptos::ev::KeyboardEvent| {
        if e.key() == "Enter" {
            let url = url_input.get();
            if !url.trim().is_empty() {
                // Spawn a new linked browse block, then collapse this one.
                canvas_state.submit_agent_link(url, Some(block_ctx.id.get_value()));
                block_ctx.expanded.set(false);
            }
        } else if e.key() == "Escape" {
            block_ctx.expanded.set(false);
        }
    };

    view! {
        <div
            class="canvas-block-browse-bar"
            // Prevent the outer block on:click from toggling reprompt.
            on:click=|e: leptos::ev::MouseEvent| e.stop_propagation()
        >
            <span class="browse-bar-icon">"🌐"</span>
            <input
                type="text"
                class="browse-bar-input"
                prop:value=move || url_input.get()
                on:input=move |e| url_input.set(event_target_value(&e))
                on:keydown=on_keydown
            />
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

            // Agent identity row (hidden for on-device synthesizer)
            <Show when=move || !is_on_device>
                <div class="prov-did-row">
                    <span class="prov-label">"AGENT"</span>
                    <span class="prov-did" title=agent_did.clone()>{agent_did_short.clone()}</span>
                </div>
            </Show>

            // Your identity row (shows who authorized this)
            <Show when=move || has_issuer_did>
                <div class="prov-did-row">
                    <span class="prov-label">"YOU"</span>
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
