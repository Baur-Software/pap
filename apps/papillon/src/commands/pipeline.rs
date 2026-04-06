#![allow(clippy::unwrap_used)]
use std::collections::{HashMap, VecDeque};

use serde_json::json;
use tauri::{AppHandle, Emitter, State};

use pap_did::PrincipalKeypair;
use papillon_shared::{
    PipelineExecutionResult, PipelineInfo, PipelineNodeType, PipelineStepEvent, PipelineStepResult,
};

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
        let seed_guard = state.principal_seed.read().unwrap();
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

/// Run a synthesizer node: compose upstream results into a single outcome
/// using the on-device LLM. Never leaves the device.
async fn run_synthesizer_node(
    state: &State<'_, AppState>,
    upstream_json: &str,
    initial_query: &str,
) -> Result<(String, serde_json::Value), PapillonError> {
    let prompt = format!(
        "You are a synthesis assistant. The user asked: \"{}\"\n\n\
         Multiple agents provided these results:\n{}\n\n\
         Provide a concise, unified answer that combines the key information from all results. \
         Focus on what the user actually wanted to know.",
        initial_query, upstream_json,
    );

    let generated = {
        let mut mm = state.model_manager.lock().await;
        mm.generate(&prompt, 512)
            .map_err(|e| PapillonError::from(format!("Synthesizer failed: {}", e)))?
    };

    let result = json!({
        "@type": "Answer",
        "agent": "on-device-synthesizer",
        "result": generated.trim(),
    });

    Ok(("synthesizer".into(), result))
}

/// Execute a pipeline: topologically sort, run each node as a handshake.
/// Upstream result_json is passed as disclosure context to downstream nodes.
#[tauri::command]
pub async fn run_pipeline(
    app: AppHandle,
    state: State<'_, AppState>,
    pipeline: PipelineInfo,
    initial_query: String,
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
                // Single upstream — pass its result directly
                upstream_data[0]
                    .get("result")
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| initial_query.clone())
            } else {
                // Multiple upstream — compose as JSON array
                let composed = json!(upstream_data
                    .iter()
                    .filter_map(|d| d.get("result"))
                    .collect::<Vec<_>>());
                composed.to_string()
            }
        } else {
            initial_query.clone()
        };

        // Dispatch based on node type: agent (PAP handshake) or synthesizer (on-device LLM)
        let node_result = match node.node_type {
            PipelineNodeType::Agent => {
                run_pipeline_node(&state, &node.agent_name, &node.action_type, &query).await
            }
            PipelineNodeType::Synthesizer => {
                run_synthesizer_node(&state, &query, &initial_query).await
            }
        };

        let step_result = match node_result {
            Ok((session_id, result_json)) => {
                node_outputs.insert(node_id.clone(), result_json.clone());
                PipelineStepResult {
                    node_id: node_id.clone(),
                    session_id,
                    success: true,
                    result_json: Some(serde_json::to_string(&result_json).unwrap_or_default()),
                    error: None,
                }
            }
            Err(e) => PipelineStepResult {
                node_id: node_id.clone(),
                session_id: String::new(),
                success: false,
                result_json: None,
                error: Some(e.message.clone()),
            },
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
}
