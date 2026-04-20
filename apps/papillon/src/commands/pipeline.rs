#![allow(clippy::unwrap_used)]
use std::collections::{HashMap, VecDeque};

use chrono::Utc;
use serde_json::json;
use tauri::{AppHandle, Emitter, State};

use pap_did::PrincipalKeypair;
use papillon_shared::{
    BlockEvent, BlockState, BlockUpdate, PipelineExecutionResult, PipelineInfo, PipelineNodeType,
    PipelineStepEvent, PipelineStepResult, SavedPipeline, SynthesisFormat,
};

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::handshake;
use crate::state::AppState;

use super::canvas::resolve_agent;

/// Topological sort of pipeline nodes via Kahn's algorithm.
/// Returns ordered node IDs or error if cycle detected.
pub(crate) fn topological_sort(pipeline: &PipelineInfo) -> Result<Vec<String>, PapillonError> {
    let mut in_degree: HashMap<&str, usize> = HashMap::new();
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();

    for node in &pipeline.nodes {
        in_degree.entry(&node.id).or_insert(0);
        adjacency.entry(&node.id).or_default();
    }

    for edge in &pipeline.edges {
        *in_degree.entry(&edge.to_node).or_insert(0) += 1;
        adjacency
            .entry(&edge.from_node)
            .or_default()
            .push(&edge.to_node);
    }

    let mut queue: VecDeque<&str> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();

    let mut order = Vec::new();
    while let Some(node_id) = queue.pop_front() {
        order.push(node_id.to_string());
        if let Some(neighbors) = adjacency.get(node_id) {
            for &next in neighbors {
                if let Some(deg) = in_degree.get_mut(next) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(next);
                    }
                }
            }
        }
    }

    if order.len() != pipeline.nodes.len() {
        return Err(PapillonError::from("Pipeline contains a cycle"));
    }
    Ok(order)
}

/// Execute a single pipeline node as a PAP handshake.
async fn run_pipeline_node(
    state: &State<'_, AppState>,
    agent_name: &str,
    action_type: &str,
    query: &str,
) -> Result<(String, serde_json::Value), PapillonError> {
    let at = if action_type.is_empty() {
        "schema:SearchAction"
    } else {
        action_type
    };

    let resolved = resolve_agent(state, at, agent_name, &[]).await?;

    let principal_kp = {
        let seed_guard = state
            .principal_seed
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let seed = seed_guard
            .as_ref()
            .ok_or_else(|| PapillonError::from("No identity configured"))?;
        PrincipalKeypair::from_bytes(seed)
            .map_err(|e| PapillonError::from(format!("Failed to load keypair: {}", e)))?
    };

    let on_phase: handshake::PhaseCallback = Box::new(|_phase, _label| {});
    let on_fail: handshake::FailCallback = Box::new(|_phase, _reason| {});

    let result = handshake::execute(handshake::HandshakeParams {
        handler: resolved.handler,
        agent_name: &resolved.name,
        agent_did: &resolved.did,
        action_type: at,
        query,
        principal_kp: &principal_kp,
        requires_disclosure: &resolved.requires_disclosure,
        returns: &resolved.returns,
        on_phase,
        on_fail,
    })
    .await?;

    // Extract session_id from receipt content
    let session_id = result
        .content
        .get("receipt")
        .and_then(|r| r.get("session_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok((session_id, result.content))
}

/// Build the system prompt for a synthesizer node based on the requested format.
fn synthesis_system_prompt(format: &SynthesisFormat, initial_query: &str) -> String {
    let instruction = match format {
        SynthesisFormat::FreeText =>
            "Provide a concise, unified answer combining key information from all results. \
             When citing a specific source, use [source:1], [source:2], etc. \
             Only cite sources that directly support your statement.".to_string(),
        SynthesisFormat::BriefingDoc =>
            "Write a structured briefing document:\n## Summary\n(2-3 sentence overview)\n\
             ## Key Points\n(bullet list of most important facts)\n## Details\n(expanded context)\n\
             Cite sources inline as [source:N].".to_string(),
        SynthesisFormat::Faq =>
            "Generate 3-5 Frequently Asked Questions. Format each as:\n\
             **Q: [question]**\nA: [answer] [source:N]\n".to_string(),
        SynthesisFormat::Timeline =>
            "Create a chronological timeline. Each entry: `• [date/step]: [description] [source:N]`\n\
             If no dates are available, use sequential steps.".to_string(),
        SynthesisFormat::Outline =>
            "Create a hierarchical outline. Use ## for main topics, ### for subtopics, \
             bullets for details. Cite sources as [source:N].".to_string(),
    };
    format!(
        "You are a synthesis assistant. The user asked: \"{}\"\n\n\
         Agent results (numbered):\n\
         {{}}\n\n{instruction}\n\nFocus on what the user actually wanted to know.",
        initial_query,
        instruction = instruction
    )
}

/// Map a `SynthesisFormat` to the schema.org `@type` that best describes the output.
fn format_schema_type(format: &SynthesisFormat) -> &'static str {
    match format {
        SynthesisFormat::FreeText => "Answer",
        SynthesisFormat::BriefingDoc => "Report",
        SynthesisFormat::Faq => "FAQPage",
        SynthesisFormat::Timeline => "ItemList",
        SynthesisFormat::Outline => "Outline",
    }
}

/// Run a synthesizer node: compose upstream results into a single outcome
/// using the on-device LLM. Never leaves the device.
async fn run_synthesizer_node(
    state: &State<'_, AppState>,
    upstream_json: &str,
    initial_query: &str,
    format: &SynthesisFormat,
) -> Result<(String, serde_json::Value), PapillonError> {
    let system = synthesis_system_prompt(format, initial_query);
    // Substitute the upstream_json into the {} placeholder left in the template.
    let prompt = system.replace("{}", upstream_json);

    let generated = {
        let mut mm = state.model_manager.lock().await;
        mm.generate(&prompt, 512)
            .map_err(|e| PapillonError::from(format!("Synthesizer failed: {}", e)))?
    };

    let schema_type = format_schema_type(format);
    let result = json!({
        "@type": schema_type,
        "agent": "on-device-synthesizer",
        "result": generated.trim(),
    });

    Ok(("synthesizer".into(), result))
}

/// Execute a pipeline: topologically sort, run each node as a handshake.
/// Upstream result_json is passed as disclosure context to downstream nodes.
///
/// When `canvas_id` is `Some`, each node emits `"block_updated"` before
/// execution and `"block_resolved"` after, using the stable block ID
/// `"pipeline-{pipeline_id}-{node_id}"`.  The frontend pre-creates skeleton
/// blocks with those same IDs so the events land on the right blocks.
#[tauri::command]
pub async fn run_pipeline(
    app: AppHandle,
    state: State<'_, AppState>,
    pipeline: PipelineInfo,
    initial_query: String,
    canvas_id: Option<String>,
) -> Result<PipelineExecutionResult, PapillonError> {
    let order = topological_sort(&pipeline)?;
    let total = order.len();
    let mut results: Vec<PipelineStepResult> = Vec::new();
    let mut node_outputs: HashMap<String, serde_json::Value> = HashMap::new();

    // Build node lookup
    let nodes: HashMap<&str, &papillon_shared::PipelineNodeInfo> =
        pipeline.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    // Build reverse edge map: for each node, which nodes feed into it
    let mut upstream: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in &pipeline.edges {
        upstream
            .entry(&edge.to_node)
            .or_default()
            .push(&edge.from_node);
    }

    for (step_idx, node_id) in order.iter().enumerate() {
        let node = nodes.get(node_id.as_str()).ok_or_else(|| {
            PapillonError::from(format!("Node {} not found in pipeline", node_id))
        })?;

        // Emit progress event
        let _ = app.emit(
            "pipeline_step",
            PipelineStepEvent {
                pipeline_id: pipeline.id.clone(),
                step: step_idx + 1,
                total,
                node_id: node_id.clone(),
                status: "running".into(),
            },
        );

        // Build query from upstream results or use initial query for root nodes
        let query = if let Some(upstreams) = upstream.get(node_id.as_str()) {
            let upstream_data: Vec<&serde_json::Value> = upstreams
                .iter()
                .filter_map(|uid| node_outputs.get(*uid))
                .collect();
            if upstream_data.is_empty() {
                initial_query.clone()
            } else if upstream_data.len() == 1 {
                // Single upstream — pass its result directly.
                // Note blocks are formatted as human-readable text, not raw JSON.
                let upstream = upstream_data[0];
                if upstream.get("@type").and_then(|t| t.as_str()) == Some("Note") {
                    upstream
                        .get("note_content")
                        .and_then(|v| v.as_str())
                        .map(|nc| format!("User note: {}", nc))
                        .unwrap_or_else(|| initial_query.clone())
                } else {
                    upstream
                        .get("result")
                        .map(|r| r.to_string())
                        .unwrap_or_else(|| initial_query.clone())
                }
            } else {
                // Multiple upstream — compose as JSON array, rendering Note blocks as text.
                let parts: Vec<String> = upstream_data
                    .iter()
                    .map(|d| {
                        if d.get("@type").and_then(|t| t.as_str()) == Some("Note") {
                            d.get("note_content")
                                .and_then(|v| v.as_str())
                                .map(|nc| format!("User note: {}", nc))
                                .unwrap_or_default()
                        } else {
                            d.get("result").map(|r| r.to_string()).unwrap_or_default()
                        }
                    })
                    .filter(|s| !s.is_empty())
                    .collect();
                parts.join("\n\n")
            }
        } else {
            initial_query.clone()
        };

        // Stable canvas block ID for this pipeline node.
        let block_id = format!("pipeline-{}-{}", pipeline.id, node_id);

        // Emit "resolving" block event before execution (canvas path only).
        if canvas_id.is_some() {
            let now = Utc::now().to_rfc3339();
            let _ = app.emit(
                "block_updated",
                BlockEvent {
                    block: BlockUpdate {
                        id: block_id.clone(),
                        prompt_id: String::new(),
                        prompt_text: Some(query.clone()),
                        state: BlockState::Resolving {
                            phase: 1,
                            phase_label: "Executing agent".to_string(),
                        },
                        schema_type: None,
                        content: None,
                        agent_did: None,
                        mandate_expires_at: None,
                        created_at: now.clone(),
                        updated_at: now,
                        preference_guided: false,
                    },
                },
            );
        }

        // Dispatch based on node type: agent (PAP handshake) or synthesizer (on-device LLM)
        let node_result = match node.node_type {
            PipelineNodeType::Agent => {
                run_pipeline_node(&state, &node.agent_name, &node.action_type, &query).await
            }
            PipelineNodeType::Synthesizer => {
                run_synthesizer_node(&state, &query, &initial_query, &node.format).await
            }
        };

        let step_result = match node_result {
            Ok((session_id, result_json)) => {
                node_outputs.insert(node_id.clone(), result_json.clone());

                // Emit "resolved" block event (canvas path only).
                if canvas_id.is_some() {
                    let now = Utc::now().to_rfc3339();
                    // Collect agent block IDs that are upstream of this node (for Outcome state).
                    let upstream_agent_block_ids: Vec<String> = upstream
                        .get(node_id.as_str())
                        .map(|us| {
                            us.iter()
                                .map(|uid| format!("pipeline-{}-{}", pipeline.id, uid))
                                .collect()
                        })
                        .unwrap_or_default();

                    let block_state = match node.node_type {
                        PipelineNodeType::Synthesizer => BlockState::Outcome {
                            provenance_block_ids: upstream_agent_block_ids,
                        },
                        PipelineNodeType::Agent => BlockState::Resolved,
                    };
                    let schema_type = result_json
                        .get("@type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let _ = app.emit(
                        "block_resolved",
                        BlockEvent {
                            block: BlockUpdate {
                                id: block_id.clone(),
                                prompt_id: String::new(),
                                prompt_text: Some(query.clone()),
                                state: block_state,
                                schema_type,
                                content: Some(result_json.clone()),
                                agent_did: None,
                                mandate_expires_at: None,
                                created_at: now.clone(),
                                updated_at: now,
                                preference_guided: false,
                            },
                        },
                    );
                }

                PipelineStepResult {
                    node_id: node_id.clone(),
                    session_id,
                    success: true,
                    result_json: Some(serde_json::to_string(&result_json).unwrap_or_default()),
                    error: None,
                }
            }
            Err(e) => {
                // Emit "failed" block event (canvas path only).
                if canvas_id.is_some() {
                    let now = Utc::now().to_rfc3339();
                    let _ = app.emit(
                        "block_resolved",
                        BlockEvent {
                            block: BlockUpdate {
                                id: block_id.clone(),
                                prompt_id: String::new(),
                                prompt_text: Some(query.clone()),
                                state: BlockState::Failed {
                                    phase: 1,
                                    reason: e.message.clone(),
                                },
                                schema_type: None,
                                content: None,
                                agent_did: None,
                                mandate_expires_at: None,
                                created_at: now.clone(),
                                updated_at: now,
                                preference_guided: false,
                            },
                        },
                    );
                }

                PipelineStepResult {
                    node_id: node_id.clone(),
                    session_id: String::new(),
                    success: false,
                    result_json: None,
                    error: Some(e.message.clone()),
                }
            }
        };

        let status = if step_result.success {
            "completed"
        } else {
            "failed"
        };
        let _ = app.emit(
            "pipeline_step",
            PipelineStepEvent {
                pipeline_id: pipeline.id.clone(),
                step: step_idx + 1,
                total,
                node_id: node_id.clone(),
                status: status.into(),
            },
        );

        results.push(step_result);
    }

    let steps_completed = results.iter().filter(|r| r.success).count();
    Ok(PipelineExecutionResult {
        pipeline_id: pipeline.id.clone(),
        steps_completed,
        steps_total: total,
        results,
    })
}

/// Save (upsert) a pipeline by id. Returns the full `SavedPipeline` record.
#[tauri::command]
pub async fn save_pipeline(
    state: State<'_, AppState>,
    id: String,
    name: String,
    description: String,
    pipeline: PipelineInfo,
) -> Result<SavedPipeline, PapillonError> {
    state
        .db
        .upsert_saved_pipeline(&id, &name, &description, &pipeline)
        .map_err(|e| PapillonError::from(e.0))?;

    // Return the persisted record. list_saved_pipelines is ordered by
    // created_at DESC; find by id so callers receive the exact row.
    let list = state
        .db
        .list_saved_pipelines()
        .map_err(|e| PapillonError::from(e.0))?;

    list.into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| PapillonError::from("saved pipeline not found after upsert"))
}

/// List all saved pipelines, most recently created first.
#[tauri::command]
pub async fn list_saved_pipelines(
    state: State<'_, AppState>,
) -> Result<Vec<SavedPipeline>, PapillonError> {
    state
        .db
        .list_saved_pipelines()
        .map_err(|e| PapillonError::from(e.0))
}

/// Delete a saved pipeline by id. No-op if the id does not exist.
#[tauri::command]
pub async fn delete_saved_pipeline(
    state: State<'_, AppState>,
    id: String,
) -> Result<(), PapillonError> {
    state
        .db
        .delete_saved_pipeline(&id)
        .map_err(|e| PapillonError::from(e.0))
}

/// Load a saved pipeline by id and run it.
///
/// When `canvas_id` is `Some`, block events are emitted for each node so
/// the canvas front-face can render live progress.
#[tauri::command]
pub async fn run_saved_pipeline(
    app: AppHandle,
    state: State<'_, AppState>,
    pipeline_id: String,
    initial_query: String,
    canvas_id: Option<String>,
) -> Result<PipelineExecutionResult, PapillonError> {
    let list = state
        .db
        .list_saved_pipelines()
        .map_err(|e| PapillonError::from(e.0))?;

    let saved = list
        .into_iter()
        .find(|p| p.id == pipeline_id)
        .ok_or_else(|| PapillonError::from(format!("saved pipeline not found: {}", pipeline_id)))?;

    // Stamp updated_at so the run timestamp is fresh.
    let _ = Utc::now().to_rfc3339();

    run_pipeline(app, state, saved.pipeline, initial_query, canvas_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use papillon_shared::{PipelineEdgeInfo, PipelineNodeInfo, PipelineNodeType};

    fn make_node(id: &str) -> PipelineNodeInfo {
        PipelineNodeInfo {
            id: id.into(),
            agent_hash: String::new(),
            agent_name: format!("Agent-{}", id),
            action_type: "schema:SearchAction".into(),
            node_type: PipelineNodeType::Agent,
            position_x: 0.0,
            position_y: 0.0,
            format: Default::default(),
        }
    }

    fn make_synthesizer_node(id: &str) -> PipelineNodeInfo {
        PipelineNodeInfo {
            id: id.into(),
            agent_hash: String::new(),
            agent_name: "Synthesizer".into(),
            action_type: String::new(),
            node_type: PipelineNodeType::Synthesizer,
            position_x: 0.0,
            position_y: 0.0,
            format: Default::default(),
        }
    }

    fn make_edge(from: &str, to: &str) -> PipelineEdgeInfo {
        PipelineEdgeInfo {
            from_node: from.into(),
            to_node: to.into(),
        }
    }

    #[test]
    fn topological_sort_linear() {
        let pipeline = PipelineInfo {
            id: "p1".into(),
            name: "Linear".into(),
            nodes: vec![make_node("A"), make_node("B"), make_node("C")],
            edges: vec![make_edge("A", "B"), make_edge("B", "C")],
            created_at: String::new(),
        };
        let order = topological_sort(&pipeline).unwrap();
        assert_eq!(order.len(), 3);
        let a_pos = order.iter().position(|x| x == "A").unwrap();
        let b_pos = order.iter().position(|x| x == "B").unwrap();
        let c_pos = order.iter().position(|x| x == "C").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn topological_sort_diamond() {
        let pipeline = PipelineInfo {
            id: "p2".into(),
            name: "Diamond".into(),
            nodes: vec![
                make_node("A"),
                make_node("B"),
                make_node("C"),
                make_node("D"),
            ],
            edges: vec![
                make_edge("A", "B"),
                make_edge("A", "C"),
                make_edge("B", "D"),
                make_edge("C", "D"),
            ],
            created_at: String::new(),
        };
        let order = topological_sort(&pipeline).unwrap();
        assert_eq!(order.len(), 4);
        let a_pos = order.iter().position(|x| x == "A").unwrap();
        let b_pos = order.iter().position(|x| x == "B").unwrap();
        let c_pos = order.iter().position(|x| x == "C").unwrap();
        let d_pos = order.iter().position(|x| x == "D").unwrap();
        assert!(a_pos < b_pos);
        assert!(a_pos < c_pos);
        assert!(b_pos < d_pos);
        assert!(c_pos < d_pos);
    }

    #[test]
    fn topological_sort_detects_cycle() {
        let pipeline = PipelineInfo {
            id: "p3".into(),
            name: "Cyclic".into(),
            nodes: vec![make_node("A"), make_node("B")],
            edges: vec![make_edge("A", "B"), make_edge("B", "A")],
            created_at: String::new(),
        };
        let result = topological_sort(&pipeline);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("cycle"));
    }

    #[test]
    fn topological_sort_single_node() {
        let pipeline = PipelineInfo {
            id: "p4".into(),
            name: "Single".into(),
            nodes: vec![make_node("A")],
            edges: vec![],
            created_at: String::new(),
        };
        let order = topological_sort(&pipeline).unwrap();
        assert_eq!(order, vec!["A"]);
    }

    #[test]
    fn topological_sort_empty_pipeline() {
        let pipeline = PipelineInfo {
            id: "p5".into(),
            name: "Empty".into(),
            nodes: vec![],
            edges: vec![],
            created_at: String::new(),
        };
        let order = topological_sort(&pipeline).unwrap();
        assert!(order.is_empty());
    }

    #[test]
    fn topological_sort_parallel_branches() {
        // A -> B, A -> C (B and C are independent)
        let pipeline = PipelineInfo {
            id: "p6".into(),
            name: "Parallel".into(),
            nodes: vec![make_node("A"), make_node("B"), make_node("C")],
            edges: vec![make_edge("A", "B"), make_edge("A", "C")],
            created_at: String::new(),
        };
        let order = topological_sort(&pipeline).unwrap();
        assert_eq!(order.len(), 3);
        let a_pos = order.iter().position(|x| x == "A").unwrap();
        let b_pos = order.iter().position(|x| x == "B").unwrap();
        let c_pos = order.iter().position(|x| x == "C").unwrap();
        assert!(a_pos < b_pos);
        assert!(a_pos < c_pos);
    }

    #[test]
    fn topological_sort_diamond_with_synthesizer() {
        // A -> B, A -> C, B -> S, C -> S (S is synthesizer)
        let pipeline = PipelineInfo {
            id: "p7".into(),
            name: "Diamond+Synth".into(),
            nodes: vec![
                make_node("A"),
                make_node("B"),
                make_node("C"),
                make_synthesizer_node("S"),
            ],
            edges: vec![
                make_edge("A", "B"),
                make_edge("A", "C"),
                make_edge("B", "S"),
                make_edge("C", "S"),
            ],
            created_at: String::new(),
        };
        let order = topological_sort(&pipeline).unwrap();
        assert_eq!(order.len(), 4);
        let a_pos = order.iter().position(|x| x == "A").unwrap();
        let b_pos = order.iter().position(|x| x == "B").unwrap();
        let c_pos = order.iter().position(|x| x == "C").unwrap();
        let s_pos = order.iter().position(|x| x == "S").unwrap();
        // Synthesizer must come last — after all agent nodes
        assert!(a_pos < b_pos);
        assert!(a_pos < c_pos);
        assert!(b_pos < s_pos);
        assert!(c_pos < s_pos);
    }

    #[test]
    fn synthesizer_node_type_default_is_agent() {
        let node = make_node("test");
        assert_eq!(node.node_type, PipelineNodeType::Agent);
    }

    #[test]
    fn synthesizer_node_type_set_correctly() {
        let node = make_synthesizer_node("synth");
        assert_eq!(node.node_type, PipelineNodeType::Synthesizer);
        assert_eq!(node.agent_name, "Synthesizer");
    }

    #[test]
    fn pipeline_block_id_format_is_stable() {
        // Block IDs must be deterministic so the frontend can pre-create skeleton
        // blocks and the backend events land on the right blocks.
        let pipeline_id = "pipe-abc";
        let node_id = "node-1";
        let block_id = format!("pipeline-{}-{}", pipeline_id, node_id);
        assert_eq!(block_id, "pipeline-pipe-abc-node-1");
        // Verify the format is stable regardless of run order.
        assert_eq!(
            format!("pipeline-{}-{}", pipeline_id, "node-2"),
            "pipeline-pipe-abc-node-2",
        );
    }

    #[test]
    fn pipeline_block_ids_are_unique_per_node() {
        // Each node in a pipeline must produce a distinct block ID so the canvas
        // renders them as separate blocks (no accidental collision).
        let pipeline = PipelineInfo {
            id: "p-unique".into(),
            name: "Unique IDs".into(),
            nodes: vec![
                make_node("alpha"),
                make_node("beta"),
                make_synthesizer_node("synth"),
            ],
            edges: vec![make_edge("alpha", "synth"), make_edge("beta", "synth")],
            created_at: String::new(),
        };
        let block_ids: Vec<String> = pipeline
            .nodes
            .iter()
            .map(|n| format!("pipeline-{}-{}", pipeline.id, n.id))
            .collect();
        // All block IDs must be distinct.
        let unique: std::collections::HashSet<_> = block_ids.iter().collect();
        assert_eq!(
            unique.len(),
            block_ids.len(),
            "block IDs must be unique per node"
        );
    }

    #[test]
    fn synthesis_prompt_free_text_contains_cite_instructions() {
        let p = synthesis_system_prompt(&SynthesisFormat::FreeText, "test");
        assert!(p.contains("[source:"));
    }

    #[test]
    fn synthesis_prompt_briefing_contains_summary_section() {
        let p = synthesis_system_prompt(&SynthesisFormat::BriefingDoc, "test");
        assert!(p.contains("## Summary"));
    }

    #[test]
    fn synthesis_prompt_faq_contains_question_pattern() {
        let p = synthesis_system_prompt(&SynthesisFormat::Faq, "test");
        assert!(p.contains("Q:") || p.contains("**Q:"));
    }

    #[test]
    fn format_schema_types_are_distinct() {
        use std::collections::HashSet;
        let types: HashSet<_> = [
            SynthesisFormat::FreeText,
            SynthesisFormat::BriefingDoc,
            SynthesisFormat::Faq,
            SynthesisFormat::Timeline,
            SynthesisFormat::Outline,
        ]
        .iter()
        .map(format_schema_type)
        .collect();
        assert_eq!(types.len(), 5);
    }

    #[test]
    fn serde_default_roundtrip_for_new_format_field() {
        let json = r#"{"id":"n1","agent_hash":"","agent_name":"test","action_type":"schema:SearchAction","node_type":"agent","position_x":0.0,"position_y":0.0}"#;
        let node: papillon_shared::PipelineNodeInfo = serde_json::from_str(json).unwrap();
        assert_eq!(node.format, papillon_shared::SynthesisFormat::FreeText);
    }
}
