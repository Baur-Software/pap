use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::block_renderer::BlockRenderer;
use crate::state::canvas::CanvasState;

// ── Canvas outcome synthesis types (mirrors Tauri backend) ────────────────

/// A synthesised summary of a single completed agent interaction episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeSummary {
    pub session_did: String,
    pub agent_did: String,
    pub agent_name: String,
    pub action: String,
    pub outcome: String,
    pub timestamp: String,
    pub receipt_hash: String,
    pub intent_summary: Option<String>,
}

/// Synthesised canvas state returned by the `get_canvas_state` Tauri command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasSummaryState {
    pub principal_did: String,
    pub episodes: Vec<EpisodeSummary>,
    pub success_count: u32,
    pub failure_count: u32,
    pub active_sessions: u32,
}

/// Agent capabilities shown as clickable tiles on the new-tab canvas.
/// Each entry is (label, example_prompt).
const AGENT_TILES: &[(&str, &str)] = &[
    ("Web Search", "search for "),
    ("Wikipedia", "tell me about "),
    ("Weather", "weather in "),
    ("Dictionary", "define "),
    ("Currency", "convert 100 USD to EUR"),
    ("Countries", "country "),
    ("Research Papers", "paper on "),
    ("GitHub Repos", "github "),
    ("Books", "book about "),
    ("Hacker News", "hacker news "),
    ("Geocoding", "where is "),
    ("Web Reader", "https://"),
    ("AI Chat", "explain "),
];

#[component]
pub fn CanvasPage() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks)
            .unwrap_or_default()
    };

    let has_blocks = move || !blocks().is_empty();

    // Group blocks by semantic links for rendering
    let grouped_blocks = move || {
        let all_blocks = blocks();
        let mut rendered: Vec<BlockGroup> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for block in &all_blocks {
            if seen.contains(&block.id) {
                continue;
            }
            seen.insert(block.id.clone());

            if block.linked_block_ids.is_empty() {
                rendered.push(BlockGroup::Single(block.clone()));
            } else {
                let mut group = vec![block.clone()];
                for linked_id in &block.linked_block_ids {
                    if !seen.contains(linked_id) {
                        if let Some(linked) = all_blocks.iter().find(|b| b.id == *linked_id) {
                            seen.insert(linked.id.clone());
                            group.push(linked.clone());
                        }
                    }
                }
                rendered.push(BlockGroup::Linked(group));
            }
        }
        rendered
    };

    view! {
        <HitlGate />

        <div class="canvas-page">
            <div class="canvas-stream">
                <Show
                    when=has_blocks
                    fallback=move || view! { <CanvasEmptyState /> }
                >
                    <For
                        each=grouped_blocks
                        key=|g| match g {
                            BlockGroup::Single(b) => format!("{}@{}", b.id, b.updated_at),
                            BlockGroup::Linked(bs) => bs
                                .iter()
                                .map(|b| format!("{}@{}", b.id, b.updated_at))
                                .collect::<Vec<_>>()
                                .join("-"),
                        }
                        children=move |group| {
                            match group {
                                BlockGroup::Single(block) => {
                                    view! { <BlockRenderer block=block /> }.into_any()
                                }
                                BlockGroup::Linked(blocks) => {
                                    view! {
                                        <div class="block-group">
                                            {blocks.into_iter().map(|block| {
                                                view! { <BlockRenderer block=block /> }
                                            }).collect::<Vec<_>>()}
                                        </div>
                                    }
                                    .into_any()
                                }
                            }
                        }
                    />
                </Show>
            </div>
        </div>
    }
}

/// Empty-state capability tiles — shown when the canvas has no blocks.
/// Each tile prefills the prompt bar so the user can complete and submit.
#[component]
fn CanvasEmptyState() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    view! {
        <div class="canvas-empty-state">
            <div class="agent-tiles">
                {AGENT_TILES.iter().map(|&(label, example)| {
                    let canvas_state = canvas_state;
                    view! {
                        <button
                            class="agent-tile"
                            on:click=move |_| {
                                canvas_state.prefill_prompt.set(Some(example.to_string()));
                                canvas_state.focus_prompt.update(|n| *n += 1);
                            }
                        >
                            <span class="agent-tile-label">{label}</span>
                            <span class="agent-tile-example">{example}</span>
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }
}

// Address bar (InlinePrompt) promoted to TopbarPrompt in components/topbar.rs.

/// Human-in-the-Loop gate — a full-screen critical action barrier.
/// Appears when `canvas_state.hitl_pending` is `Some`.
#[component]
fn HitlGate() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let authorize = move |_| {
        canvas_state.hitl_pending.set(None);
    };

    let reject = move |_| {
        canvas_state.hitl_pending.set(None);
    };

    view! {
        <Show when=move || canvas_state.hitl_pending.get().is_some()>
            {move || {
                let req = canvas_state.hitl_pending.get().unwrap();
                let is_critical = req.risk_level == "CRITICAL";
                view! {
                    <div class="hitl-overlay">
                        <div class="hitl-gate" class:hitl-gate-critical=is_critical>
                            <div class="hitl-header">
                                <span class="hitl-risk-badge" class:hitl-risk-critical=is_critical>
                                    {req.risk_level.clone()}
                                </span>
                                <span class="hitl-title">"HUMAN_GATE_REQUIRED"</span>
                            </div>

                            <div class="hitl-agent-row">
                                <span class="hitl-label">"AGENT"</span>
                                <span class="hitl-value">{req.agent_name.clone()}</span>
                            </div>
                            <div class="hitl-agent-row">
                                <span class="hitl-label">"ACTION"</span>
                                <span class="hitl-value">{
                                    req.action_type.strip_prefix("schema:")
                                        .unwrap_or(&req.action_type)
                                        .to_string()
                                }</span>
                            </div>

                            <div class="hitl-description">{req.description.clone()}</div>

                            {
                                let props_check = req.disclosure_props.clone();
                                let props_render = req.disclosure_props.clone();
                                view! {
                                    <Show when=move || !props_check.is_empty()>
                                        <div class="hitl-disclosure">
                                            <div class="hitl-disclosure-label">"DISCLOSURE_REQUIRED"</div>
                                            <div class="hitl-disclosure-props">
                                                {props_render.iter().map(|p| {
                                                    view! { <span class="hitl-prop-tag">{p.clone()}</span> }
                                                }).collect::<Vec<_>>()}
                                            </div>
                                        </div>
                                    </Show>
                                }
                            }

                            <div class="hitl-actions">
                                <button class="hitl-reject-btn" on:click=reject>
                                    "[ REJECT ]"
                                </button>
                                <button class="hitl-authorize-btn" on:click=authorize>
                                    "[ AUTHORIZE ]"
                                </button>
                            </div>

                            <div class="hitl-footnote">
                                "This action requires your explicit authorization. "
                                "PAP protocol v1 \u{2014} Zero-trust principal gate."
                            </div>
                        </div>
                    </div>
                }
            }}
        </Show>
    }
}

/// Outcome synthesis panel — loads completed episode summaries from the
/// persistent episode store via the `get_canvas_state` Tauri command and
/// renders them as a timeline with wing-spectrum status indicators.
///
/// - Teal  (#2ec4a0) — success / resolved
/// - Gold  (#f0a030) — in-progress (active sessions)
/// - Coral (#e8706a) — failure / error
///
/// Only rendered when Tauri IPC is available; silently hidden in browser mode.
#[component]
fn OutcomeSummary() -> impl IntoView {
    let canvas_data = RwSignal::new(None::<CanvasSummaryState>);
    let loading = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    // Load canvas state on mount (Tauri path only)
    Effect::new(move || {
        if !bridge::tauri_available() {
            return;
        }
        loading.set(true);
        spawn_local(async move {
            match bridge::invoke_no_args::<CanvasSummaryState>("get_canvas_state").await {
                Ok(state) => {
                    canvas_data.set(Some(state));
                    error.set(None);
                }
                Err(e) => {
                    error.set(Some(e));
                }
            }
            loading.set(false);
        });
    });

    let has_episodes = move || {
        canvas_data
            .get()
            .as_ref()
            .map(|s| !s.episodes.is_empty())
            .unwrap_or(false)
    };

    view! {
        <Show when=move || bridge::tauri_available()>
            <div class="outcome-summary">
                <div class="outcome-summary-header">
                    <span class="outcome-summary-label">"OUTCOME_SYNTHESIS"</span>
                    <Show when=move || loading.get()>
                        <span class="outcome-loading-indicator">"..."</span>
                    </Show>
                </div>

                <Show when=move || error.get().is_some()>
                    <div class="outcome-error">
                        {move || error.get().unwrap_or_default()}
                    </div>
                </Show>

                <Show when=move || canvas_data.get().is_some() && !loading.get()>
                    {move || {
                        let state = canvas_data.get().unwrap();
                        let did_short = if state.principal_did.len() > 20 {
                            format!("{}...", &state.principal_did[..20])
                        } else {
                            state.principal_did.clone()
                        };
                        view! {
                            <div class="outcome-principal">
                                <span class="outcome-key">"DID"</span>
                                <span class="outcome-did">{did_short}</span>
                            </div>
                            <div class="outcome-stats">
                                <div class="outcome-stat outcome-stat-success">
                                    <span class="outcome-stat-icon">
                                        // Checkmark SVG — success indicator
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                            <path d="M20 6 9 17l-5-5"/>
                                        </svg>
                                    </span>
                                    <span class="outcome-stat-val">{state.success_count}</span>
                                </div>
                                <div class="outcome-stat outcome-stat-failure">
                                    <span class="outcome-stat-icon">
                                        // X SVG — failure indicator
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                            <path d="M18 6 6 18M6 6l12 12"/>
                                        </svg>
                                    </span>
                                    <span class="outcome-stat-val">{state.failure_count}</span>
                                </div>
                                <div class="outcome-stat outcome-stat-active">
                                    <span class="outcome-stat-icon">
                                        // Clock SVG — in-progress indicator
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                            <circle cx="12" cy="12" r="10"/>
                                            <path d="M12 6v6l4 2"/>
                                        </svg>
                                    </span>
                                    <span class="outcome-stat-val">{state.active_sessions}</span>
                                </div>
                            </div>
                        }
                    }}
                </Show>

                <Show when=has_episodes>
                    <div class="outcome-divider" />
                    <div class="outcome-timeline">
                        <For
                            each=move || {
                                canvas_data
                                    .get()
                                    .map(|s| s.episodes)
                                    .unwrap_or_default()
                            }
                            key=|ep| ep.receipt_hash.clone()
                            children=move |ep| {
                                let action_display = ep
                                    .action
                                    .strip_prefix("schema:")
                                    .unwrap_or(&ep.action)
                                    .to_string();
                                let ts_short = ep.timestamp.chars().take(16).collect::<String>();
                                let outcome_class = match ep.outcome.as_str() {
                                    "success" => "outcome-entry outcome-entry-success",
                                    "failure" | "rejected" => "outcome-entry outcome-entry-failure",
                                    _ => "outcome-entry outcome-entry-pending",
                                };
                                // Outcome icon rendered as an inline SVG via a
                                // type-erased AnyView to avoid match-arm type mismatch.
                                let outcome_icon = match ep.outcome.as_str() {
                                    "success" => view! {
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                            <path d="M20 6 9 17l-5-5"/>
                                        </svg>
                                    }.into_any(),
                                    "failure" | "rejected" => view! {
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                            <path d="M18 6 6 18M6 6l12 12"/>
                                        </svg>
                                    }.into_any(),
                                    _ => view! {
                                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                            <circle cx="12" cy="12" r="10"/>
                                            <path d="M12 6v6l4 2"/>
                                        </svg>
                                    }.into_any(),
                                };
                                let agent_name = ep.agent_name.clone();
                                let intent = ep.intent_summary.clone();
                                view! {
                                    <div class=outcome_class>
                                        <span class="outcome-entry-icon">{outcome_icon}</span>
                                        <div class="outcome-entry-body">
                                            <div class="outcome-entry-top">
                                                <span class="outcome-entry-agent">{agent_name}</span>
                                                <span class="outcome-entry-action">{action_display}</span>
                                            </div>
                                            {move || {
                                                if let Some(ref summary) = intent {
                                                    let s = summary.clone();
                                                    view! {
                                                        <div class="outcome-entry-intent">{s}</div>
                                                    }.into_any()
                                                } else {
                                                    view! { <span /> }.into_any()
                                                }
                                            }}
                                            <div class="outcome-entry-meta">
                                                <span class="outcome-entry-ts">{ts_short}</span>
                                                <span class="outcome-entry-hash">{ep.receipt_hash.clone()}</span>
                                            </div>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </div>
                </Show>

                <Show when=move || !has_episodes() && !loading.get() && bridge::tauri_available()>
                    <div class="outcome-empty">"NO_COMPLETED_EPISODES"</div>
                </Show>
            </div>
        </Show>
    }
}

#[derive(Clone)]
enum BlockGroup {
    Single(papillon_shared::CanvasBlock),
    Linked(Vec<papillon_shared::CanvasBlock>),
}
