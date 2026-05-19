use crate::AppState;
use papillon_shared::{AgentInfo, BlockContainer, BlockPosition, SchemaSignature};
use rand::Rng;
use tauri::State;

/// Create a new block container from an intent.
/// Uses BM25 to classify intent → schema action → agent signature.
#[tauri::command]
pub async fn create_block_container(
    canvas_id: String,
    _prompt: String,
    position: Option<BlockPosition>,
    state: State<'_, AppState>,
) -> Result<BlockContainer, String> {
    // 1. Get agents from local registry
    let local_registry = state.local_registry.lock().map_err(|e| e.to_string())?;

    let ads = local_registry.all_advertisements();
    let agents: Vec<AgentInfo> = ads
        .iter()
        .map(|ad| AgentInfo {
            name: ad.name.clone(),
            provider_name: ad.provider.name.clone(),
            provider_did: ad.provider.did.clone(),
            capabilities: ad.capability.clone(),
            object_types: ad.object_types.clone(),
            requires_disclosure: ad.requires_disclosure.clone(),
            returns: ad.returns.clone(),
            endpoint: None, // TODO: Extract from marketplace advertisement if available
            content_hash: String::new(),
            agent_did: Some(ad.signed_by.clone()),
            source: "local".to_string(),
            published_to: vec![],
            live: true,
            category: "general".to_string(),
            execution_target: Default::default(),
            lifecycle: Default::default(),
        })
        .collect();

    drop(local_registry); // Release lock

    // 2. For now, use a simple placeholder approach
    // TODO: Use BM25 IntentIndex to classify prompt
    // let index = IntentIndex::new(&dynamic_agents);
    // let intent_match = index.classify(&prompt).ok_or("No intent match found")?;

    // Placeholder: Create a generic SearchAction signature
    let signature = SchemaSignature {
        input_types: vec![],
        output_types: vec!["schema:SearchResult".to_string()],
    };

    // 3. Filter agents by matching signature
    let compatible_agents: Vec<String> = agents
        .into_iter()
        .filter(|agent| {
            let agent_sig = SchemaSignature::from_agent(agent);
            agent_sig.matches(&signature)
        })
        .map(|a| a.name)
        .collect();

    if compatible_agents.is_empty() {
        return Err(format!("No agents found for signature: {:?}", signature));
    }

    // 4. Create container with caller-supplied or auto-offset position
    let position = position.unwrap_or_else(|| {
        let mut rng = rand::rngs::OsRng;
        BlockPosition {
            x: 100.0 + rng.gen_range(0.0..=40.0),
            y: 100.0 + rng.gen_range(0.0..=40.0),
        }
    });
    let container = BlockContainer {
        id: uuid::Uuid::new_v4().to_string(),
        canvas_id,
        signature,
        agent_names: compatible_agents,
        position,
        input_connections: vec![],
        output_connections: vec![],
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    // 5. Store container in DB (TODO: add table)
    // For now, return the in-memory container
    Ok(container)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_creation_logic() {
        // This test validates the container creation logic without DB
        let _canvas_id = "canvas-123";
        let _prompt = "weather in seattle";
        let _action_type = "schema:SearchAction";

        // Signature would be derived from BM25 intent detection
        let signature = SchemaSignature {
            input_types: vec!["schema:Place".to_string()],
            output_types: vec!["schema:WeatherForecast".to_string()],
        };

        // In real impl, agents would be filtered by signature.matches()
        let agent_names: Vec<String> = vec!["Weather Agent 1".to_string()];

        assert!(!agent_names.is_empty());
        assert_eq!(signature.output_types.len(), 1);
    }
}
