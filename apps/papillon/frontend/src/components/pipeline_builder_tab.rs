use leptos::prelude::*;
use papillon_shared::{BlockState, CanvasBlock, PipelineNodeType, SavedPipeline, SynthesisFormat};
use wasm_bindgen_futures::spawn_local;

use crate::bridge;
use crate::state::canvas::{CanvasSide, CanvasState};

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
pub fn PipelineBuilderTab() -> impl IntoView {
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
                                retention_warning: None,
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
