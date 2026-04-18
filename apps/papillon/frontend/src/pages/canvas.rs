use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock, PipelineNodeType, SavedPipeline, SynthesisFormat};
use serde::{Deserialize, Serialize};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::components::block_renderer::BlockRenderer;
use crate::components::source_panel::SourcePanel;
use crate::state::canvas::{filter_messages_by_canvas, CanvasSide, CanvasState};

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

    let is_back = move || canvas_state.canvas_side.get() == CanvasSide::Back;

    view! {
        <HitlGate />

        <div class="canvas-page">
            // Flip container.
            <div
                class="canvas-flip-container"
                class:flipped=is_back
            >
                // Front face: rendered blocks + chat thread.
                <div class="canvas-face front">
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
                        <button
                            class="add-note-btn"
                            title="Add a note"
                            on:click=move |_| canvas_state.create_note(String::new(), String::new())
                        >
                            "+ Note"
                        </button>
                    </div>
                    <CanvasChatThread />
                </div>

                // Back face: three-tab panel — Sources / Build / History.
                <div class="canvas-face back">
                    <CanvasBackFace />
                </div>
            </div>
        </div>
    }
}

/// Chat thread component — shows conversation messages and a simple input.
#[component]
fn CanvasChatThread() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();
    let input_value = RwSignal::new(String::new());

    let on_keydown = move |e: leptos::ev::KeyboardEvent| {
        if e.key() == "Enter" {
            let text = input_value.get();
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() {
                canvas_state.submit_prompt(trimmed.clone());
                canvas_state.add_message("user", &trimmed, None);
                input_value.set(String::new());
            }
        }
    };

    // Only show messages belonging to the currently active canvas.
    let active_messages = move || {
        let active_id = canvas_state.current_canvas_id.get();
        filter_messages_by_canvas(
            &canvas_state.canvas_messages.get(),
            active_id.as_deref(),
        )
    };

    view! {
        <div class="canvas-chat-thread">
            <For
                each=active_messages
                key=|msg| msg.id.clone()
                children=move |msg| {
                    let is_user = msg.role == "user";
                    let cls = if is_user { "chat-message-user" } else { "chat-message-assistant" };
                    let content = msg.content.clone();
                    let block_id = msg.block_id.clone();
                    view! {
                        <div class=cls>
                            {content}
                            {move || {
                                if !is_user {
                                    if let Some(ref bid) = block_id {
                                        let bid_short = if bid.len() > 8 {
                                            format!("{}...", &bid[..8])
                                        } else {
                                            bid.clone()
                                        };
                                        view! {
                                            <span class="chat-block-link">
                                                {format!(" \u{2192} block:{}", bid_short)}
                                            </span>
                                        }.into_any()
                                    } else {
                                        view! { <span /> }.into_any()
                                    }
                                } else {
                                    view! { <span /> }.into_any()
                                }
                            }}
                        </div>
                    }
                }
            />
        </div>
        <div class="canvas-chat-input">
            <input
                type="text"
                placeholder="Ask anything..."
                prop:value=move || input_value.get()
                on:input=move |e| input_value.set(event_target_value(&e))
                on:keydown=on_keydown
            />
        </div>
    }
}

/// Back-face container with three tabs: Sources, Build, History.
///
/// - **Sources** — `SourcePanel`: all resolved blocks as draggable reference chips.
/// - **Build**   — placeholder until the Pipeline Builder lands.
/// - **History** — the existing `CanvasWorkflowPipeline` block list (moved here).
#[component]
fn CanvasBackFace() -> impl IntoView {
    // "sources" | "build" | "history"
    let active_tab: RwSignal<&'static str> = RwSignal::new("sources");

    view! {
        <div class="canvas-back-face">
            // Tab bar
            <div class="back-face-tabs" role="tablist">
                {["sources", "build", "history"].iter().map(|&tab| {
                    view! {
                        <button
                            class="back-face-tab"
                            class:back-face-tab--active=move || active_tab.get() == tab
                            role="tab"
                            on:click=move |_| active_tab.set(tab)
                        >
                            {match tab {
                                "sources" => "Sources",
                                "build"   => "Build",
                                _         => "History",
                            }}
                        </button>
                    }
                }).collect::<Vec<_>>()}
            </div>

            // Tab panels
            <div class="back-face-panel">
                <Show when=move || active_tab.get() == "sources">
                    <SourcePanel />
                </Show>
                <Show when=move || active_tab.get() == "build">
                    <PipelineBuilderTab />
                </Show>
                <Show when=move || active_tab.get() == "history">
                    <CanvasWorkflowPipeline />
                </Show>
            </div>
        </div>
    }
}

/// Pipeline Builder tab — lets the user select a saved pipeline, type a query,
/// and run it with live block-level progress on the canvas front face.
///
/// On "Run":
/// 1. Pre-creates skeleton `Resolving` blocks for every node in the pipeline
///    using stable IDs `"pipeline-{pipeline_id}-{node_id}"`.
/// 2. Flips the canvas face to Front so the blocks are visible immediately.
/// 3. Calls `run_saved_pipeline` with `canvas_id` so the backend emits
///    `block_updated` / `block_resolved` events that land on those pre-created blocks.
#[component]
fn PipelineBuilderTab() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    // List of saved pipelines loaded from the backend.
    let pipelines: RwSignal<Vec<SavedPipeline>> = RwSignal::new(Vec::new());
    let loading = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let selected_pipeline_id: RwSignal<Option<String>> = RwSignal::new(None);
    let query_text = RwSignal::new(String::new());
    let running = RwSignal::new(false);
    // Synthesis format for synthesizer nodes in the selected pipeline.
    // "free_text" | "briefing_doc" | "faq" | "timeline" | "outline"
    let synthesis_format: RwSignal<String> = RwSignal::new("free_text".to_string());

    // Load pipelines on mount.
    Effect::new(move |_| {
        if !bridge::tauri_available() {
            return;
        }
        loading.set(true);
        spawn_local(async move {
            match bridge::invoke_no_args::<Vec<SavedPipeline>>("list_saved_pipelines").await {
                Ok(list) => {
                    pipelines.set(list);
                    error.set(None);
                }
                Err(e) => {
                    error.set(Some(format!("Failed to load pipelines: {}", e)));
                }
            }
            loading.set(false);
        });
    });

    let do_run = move || {
        let pid = match selected_pipeline_id.get() {
            Some(p) => p,
            None => return,
        };
        let query = query_text.get();
        if query.trim().is_empty() {
            return;
        }

        // Resolve the canvas ID — create one if there is none.
        let canvas_id = {
            let existing = canvas_state.current_canvas_id.get_untracked();
            match existing {
                Some(id) => id,
                None => canvas_state.new_canvas(),
            }
        };

        // Find the selected pipeline to get node IDs for pre-creation.
        // Also apply the chosen synthesis format to any synthesizer nodes.
        let fmt_str = synthesis_format.get_untracked();
        let chosen_format = match fmt_str.as_str() {
            "briefing_doc" => SynthesisFormat::BriefingDoc,
            "faq" => SynthesisFormat::Faq,
            "timeline" => SynthesisFormat::Timeline,
            "outline" => SynthesisFormat::Outline,
            _ => SynthesisFormat::FreeText,
        };
        let selected_pipeline = pipelines.get_untracked()
            .into_iter()
            .find(|p| p.id == pid);

        // Patched pipeline with format applied to synthesizer nodes.
        let patched_pipeline = selected_pipeline.as_ref().map(|sp| {
            let mut patched = sp.clone();
            for node in patched.pipeline.nodes.iter_mut() {
                if node.node_type == PipelineNodeType::Synthesizer {
                    node.format = chosen_format.clone();
                }
            }
            patched
        });

        if let Some(ref sp) = patched_pipeline {
            // Pre-create skeleton blocks so they appear immediately on the front face.
            let pipeline_id = sp.pipeline.id.clone();
            canvas_state.canvases.update(|cs| {
                if let Some(canvas) = cs.iter_mut().find(|c| c.id == canvas_id) {
                    for node in &sp.pipeline.nodes {
                        let block_id = format!("pipeline-{}-{}", pipeline_id, node.id);
                        // Only insert if not already present (idempotent on re-run).
                        if !canvas.blocks.iter().any(|b| b.id == block_id) {
                            let now = js_sys::Date::new_0()
                                .to_iso_string()
                                .as_string()
                                .unwrap_or_default();
                            canvas.blocks.push(CanvasBlock {
                                id: block_id,
                                prompt_id: String::new(),
                                prompt_text: Some(query.clone()),
                                state: BlockState::Resolving {
                                    phase: 1,
                                    phase_label: "Queued".into(),
                                },
                                schema_type: None,
                                content: None,
                                linked_block_ids: Vec::new(),
                                agent_did: None,
                                mandate_expires_at: None,
                                preference_guided: false,
                                auto_expand: false,
                                created_at: now.clone(),
                                updated_at: now,
                            });
                        }
                    }
                    canvas.updated_at = js_sys::Date::new_0()
                        .to_iso_string()
                        .as_string()
                        .unwrap_or_default();
                }
            });
        }

        // Flip to front face so user sees the resolving blocks immediately.
        canvas_state.canvas_side.set(CanvasSide::Front);
        running.set(true);

        let canvas_id_clone = canvas_id.clone();
        let pid_clone = pid.clone();
        let query_clone = query.clone();
        let pipeline_for_run = patched_pipeline;
        spawn_local(async move {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct RunArgs {
                pipeline_id: String,
                initial_query: String,
                canvas_id: Option<String>,
            }
            // If we have a patched pipeline with synthesizer format overrides, run
            // it directly (run_pipeline) so the format is honoured.  Fall back to
            // run_saved_pipeline for pipelines without synthesizer nodes.
            if let Some(sp) = pipeline_for_run {
                let has_synth = sp.pipeline.nodes.iter()
                    .any(|n| n.node_type == PipelineNodeType::Synthesizer);
                if has_synth {
                    #[derive(serde::Serialize)]
                    #[serde(rename_all = "camelCase")]
                    struct RunPipelineArgs {
                        pipeline: papillon_shared::PipelineInfo,
                        initial_query: String,
                        canvas_id: Option<String>,
                    }
                    let args = RunPipelineArgs {
                        pipeline: sp.pipeline,
                        initial_query: query_clone,
                        canvas_id: Some(canvas_id_clone),
                    };
                    let _ = bridge::invoke::<_, serde_json::Value>("run_pipeline", &args).await;
                    running.set(false);
                    return;
                }
            }
            let args = RunArgs {
                pipeline_id: pid_clone,
                initial_query: query_clone,
                canvas_id: Some(canvas_id_clone),
            };
            let _ = bridge::invoke::<_, serde_json::Value>("run_saved_pipeline", &args).await;
            running.set(false);
        });
    };
    let on_run_click = move |_: leptos::ev::MouseEvent| do_run();
    let on_run_keydown = move |e: leptos::ev::KeyboardEvent| {
        if e.key() == "Enter" {
            do_run();
        }
    };

    let has_pipelines = move || !pipelines.get().is_empty();

    view! {
        <div class="pipeline-builder-tab">
            <Show when=move || loading.get()>
                <div class="pipeline-loading">"Loading pipelines..."</div>
            </Show>
            <Show when=move || error.get().is_some()>
                <div class="pipeline-error">
                    {move || error.get().unwrap_or_default()}
                </div>
            </Show>
            <Show
                when=has_pipelines
                fallback=move || view! {
                    <div class="pipeline-empty">
                        "No saved pipelines. Build one in the Pipeline Editor."
                    </div>
                }
            >
                <div class="pipeline-builder-form">
                    <label class="pipeline-select-label">"Pipeline"</label>
                    <select
                        class="pipeline-select"
                        on:change=move |e| {
                            let val = event_target_value(&e);
                            selected_pipeline_id.set(if val.is_empty() { None } else { Some(val) });
                        }
                    >
                        <option value="">"-- Select a pipeline --"</option>
                        {move || pipelines.get().into_iter().map(|p| {
                            let id = p.id.clone();
                            let name = p.name.clone();
                            view! {
                                <option value=id>{name}</option>
                            }
                        }).collect::<Vec<_>>()}
                    </select>

                    <label class="pipeline-query-label">"Query"</label>
                    <input
                        type="text"
                        class="pipeline-query-input"
                        placeholder="Enter your query..."
                        prop:value=move || query_text.get()
                        on:input=move |e| query_text.set(event_target_value(&e))
                        on:keydown=on_run_keydown
                    />

                    <label class="pipeline-format-label">"Synthesis Format"</label>
                    <select
                        class="pipeline-format-select"
                        on:change=move |e| synthesis_format.set(event_target_value(&e))
                    >
                        <option value="free_text" selected=move || synthesis_format.get() == "free_text">"Free Text"</option>
                        <option value="briefing_doc" selected=move || synthesis_format.get() == "briefing_doc">"Briefing Doc"</option>
                        <option value="faq" selected=move || synthesis_format.get() == "faq">"FAQ"</option>
                        <option value="timeline" selected=move || synthesis_format.get() == "timeline">"Timeline"</option>
                        <option value="outline" selected=move || synthesis_format.get() == "outline">"Outline"</option>
                    </select>

                    <button
                        class="pipeline-run-btn"
                        class:pipeline-run-btn--running=move || running.get()
                        disabled=move || running.get() || selected_pipeline_id.get().is_none()
                        on:click=on_run_click
                    >
                        {move || if running.get() { "Running..." } else { "Run" }}
                    </button>
                </div>
            </Show>
        </div>
    }
}

/// Workflow pipeline — lists all blocks as workflow cards on the back face.
#[component]
fn CanvasWorkflowPipeline() -> impl IntoView {
    let canvas_state = expect_context::<CanvasState>();

    let blocks = move || {
        canvas_state
            .current_canvas()
            .map(|c| c.blocks)
            .unwrap_or_default()
    };

    let has_blocks = move || !blocks().is_empty();

    view! {
        <div class="canvas-workflow-pipeline">
            <Show
                when=has_blocks
                fallback=move || view! {
                    <div class="workflow-empty-state">
                        "No blocks yet. Switch to Rendered view and submit a prompt."
                    </div>
                }
            >
                <For
                    each=blocks
                    key=|b| format!("{}@{}", b.id, b.updated_at)
                    children=move |block| {
                        let block_id = block.id.clone();
                        let block_id_retry = block_id.clone();
                        let state_label = match &block.state {
                            papillon_shared::BlockState::Resolved => "resolved",
                            papillon_shared::BlockState::Resolving { .. } => "resolving",
                            papillon_shared::BlockState::Failed { .. } => "failed",
                            papillon_shared::BlockState::Ghost { .. } => "ghost",
                            papillon_shared::BlockState::AwaitingApproval { .. } => "resolving",
                            papillon_shared::BlockState::Outcome { .. } => "resolved",
                            papillon_shared::BlockState::Guide { .. } => "guide",
                            papillon_shared::BlockState::Note { .. } => "note",
                        };
                        let badge_class = format!("wf-state-badge {}", state_label);
                        let query = block.prompt_text.clone().unwrap_or_else(|| block_id.clone());
                        let schema = block.schema_type.clone().unwrap_or_default();
                        let agent = block.agent_did.clone().unwrap_or_default();
                        let agent_short = if agent.len() > 20 {
                            format!("{}...", &agent[..20])
                        } else {
                            agent.clone()
                        };
                        let expires = block.mandate_expires_at.clone().unwrap_or_default();
                        let has_agent = !agent.is_empty();
                        let has_expires = !expires.is_empty();
                        let id_short = if block_id.len() > 8 {
                            format!("{}...", &block_id[..8])
                        } else {
                            block_id.clone()
                        };
                        view! {
                            <div class="workflow-block-card">
                                <div class="wf-header-row">
                                    <span class="wf-meta">{id_short}</span>
                                    {move || {
                                        if !schema.is_empty() {
                                            view! {
                                                <span class="wf-meta">
                                                    {format!(" \u{00b7} {}", schema.trim_start_matches("schema:"))}
                                                </span>
                                            }.into_any()
                                        } else {
                                            view! { <span /> }.into_any()
                                        }
                                    }}
                                    <span class=badge_class>{state_label}</span>
                                </div>
                                <div class="wf-query">{query}</div>
                                <Show when=move || has_agent>
                                    <div class="wf-meta">{agent_short.clone()}</div>
                                </Show>
                                <Show when=move || has_expires>
                                    <div class="wf-meta">{format!("expires {}", &expires[..16.min(expires.len())])}</div>
                                </Show>
                                <button
                                    class="btn-retry"
                                    on:click=move |e: leptos::ev::MouseEvent| {
                                        e.stop_propagation();
                                        canvas_state.retry_block(block_id_retry.clone());
                                    }
                                >
                                    "Re-run"
                                </button>
                            </div>
                        }
                    }
                />
            </Show>
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
