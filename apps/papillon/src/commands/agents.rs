use pap_agents::{DynamicAgentDef, DynamicAgentSource};
use pap_did::PrincipalKeypair;
use pap_marketplace::AgentAdvertisement;
use papillon_shared::types::AgentInfo;

use crate::db::prelude::DatabaseOps;
use crate::state::AppState;

// ── Helper ────────────────────────────────────────────────────────────────────

fn source_to_str(source: &DynamicAgentSource) -> &'static str {
    match source {
        DynamicAgentSource::Catalog => "catalog",
        DynamicAgentSource::UserCreated => "user_created",
        DynamicAgentSource::Generated => "generated",
    }
}

fn def_to_agent_info(def: &DynamicAgentDef) -> AgentInfo {
    AgentInfo {
        name: def.name.clone(),
        provider_name: def.provider.clone(),
        provider_did: def.agent_did.clone().unwrap_or_default(),
        capabilities: vec![def.action.clone()],
        object_types: def.object_types.clone(),
        requires_disclosure: def.requires_disclosure.clone(),
        returns: def.returns.clone(),
        endpoint: None,
        content_hash: String::new(),
        agent_did: def.agent_did.clone(),

        source: source_to_str(&def.source).to_owned(),
        published_to: def.published_to.clone(),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// List all local agents: compiled + catalog + user_created + generated.
/// Returns AgentInfo for each. No sensitive fields.
#[tauri::command]
pub async fn list_local_agents(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<AgentInfo>, String> {
    let registry = state
        .local_registry
        .lock()
        .map_err(|e| format!("Registry lock poisoned: {e}"))?;

    let ads = registry.all_advertisements();
    let db_defs = state.db.load_all_agents().unwrap_or_default();

    let agents: Vec<AgentInfo> = ads
        .iter()
        .map(|ad| {
            let db_def = db_defs
                .iter()
                .find(|d| d.agent_did.as_deref() == Some(ad.provider.did.as_str()));
            AgentInfo {
                name: ad.name.clone(),
                provider_name: ad.provider.name.clone(),
                provider_did: ad.provider.did.clone(),
                capabilities: ad.capability.clone(),
                object_types: ad.object_types.clone(),
                requires_disclosure: ad.requires_disclosure.clone(),
                returns: ad.returns.clone(),
                endpoint: None,
                content_hash: ad.hash(),
                agent_did: Some(ad.provider.did.clone()),

                source: db_def
                    .map(|d| source_to_str(&d.source).to_owned())
                    .unwrap_or_else(|| "compiled".to_owned()),
                published_to: db_def.map(|d| d.published_to.clone()).unwrap_or_default(),
            }
        })
        .collect();

    Ok(agents)
}

/// Save a dynamic agent: generate keypair → insert into DB → register live.
/// Returns AgentInfo (no sensitive fields).
#[tauri::command]
pub async fn save_agent(
    state: tauri::State<'_, AppState>,
    mut def: DynamicAgentDef,
) -> Result<AgentInfo, String> {
    // Validate URL safety if endpoint present
    if let Some(ref ep) = def.endpoint {
        if !pap_agents::is_safe_url(&ep.url_template) {
            return Err(format!(
                "Endpoint URL failed safety check: {}",
                ep.url_template
            ));
        }
    }

    // Generate operator keypair and derive DID
    let kp = PrincipalKeypair::generate();
    let agent_did = kp.did();
    def.operator_key_seed = Some(kp.signing_key().to_bytes());
    def.agent_did = Some(agent_did.clone());

    let now = chrono::Utc::now().to_rfc3339();
    def.created_at = now.clone();
    def.updated_at = now;

    // Persist first
    state
        .db
        .insert_agent(&def)
        .map_err(|e| format!("Failed to persist agent: {e}"))?;

    // Retain the keypair for handshake co-signing
    {
        let mut keypairs = state
            .agent_keypairs
            .write()
            .map_err(|e| format!("Keypair lock poisoned: {e}"))?;
        keypairs.insert(def.name.clone(), kp);
    }

    // Build an AgentAdvertisement and register in local_registry
    {
        // Re-load stored def to get the seed for signing
        let stored = state
            .db
            .load_all_agents()
            .unwrap_or_default()
            .into_iter()
            .find(|d| d.agent_did.as_deref() == Some(&agent_did))
            .ok_or("Agent not found after insert")?;

        let seed = stored
            .operator_key_seed
            .ok_or("operator_key_seed missing after insert")?;
        let kp_sign = PrincipalKeypair::from_bytes(&seed)
            .map_err(|e| format!("Failed to reconstruct keypair: {e}"))?;

        let mut ad = AgentAdvertisement::new(
            &def.name,
            &def.provider,
            &agent_did,
            vec![def.action.clone()],
            def.object_types.clone(),
            def.requires_disclosure.clone(),
            def.returns.clone(),
        );
        ad.sign(kp_sign.signing_key())
            .expect("Ed25519 is always supported");

        let mut reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        // Allow duplicate hash on re-save by ignoring DuplicateAdvertisement
        let _ = reg.register_local(ad);
    }

    Ok(def_to_agent_info(&def))
}

/// Delete a dynamic agent by DID.
#[tauri::command]
pub async fn delete_agent(
    state: tauri::State<'_, AppState>,
    agent_did: String,
) -> Result<(), String> {
    state
        .db
        .delete_agent(&agent_did)
        .map_err(|e| format!("Failed to delete agent from DB: {e}"))?;

    // Remove from live registry by hash — find the matching ad first
    {
        let mut reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        let hash = reg
            .all_advertisements()
            .iter()
            .find(|ad| ad.provider.did == agent_did)
            .map(|ad| ad.hash());
        if let Some(h) = hash {
            reg.remove_by_hash(&h);
        }
    }

    // Remove from keypairs
    {
        let mut keypairs = state
            .agent_keypairs
            .write()
            .map_err(|e| format!("Keypair lock poisoned: {e}"))?;
        keypairs.retain(|_name, kp| kp.did() != agent_did);
    }

    Ok(())
}

/// Update a dynamic agent definition. Preserves the operator keypair (DID stable).
#[tauri::command]
pub async fn update_agent(
    state: tauri::State<'_, AppState>,
    mut def: DynamicAgentDef,
) -> Result<AgentInfo, String> {
    let agent_did = def
        .agent_did
        .clone()
        .ok_or("update_agent: agent_did must be set")?;

    // Reload immutable fields from DB (never trust frontend-supplied seed)
    let stored = state
        .db
        .load_all_agents()
        .unwrap_or_default()
        .into_iter()
        .find(|d| d.agent_did.as_deref() == Some(&agent_did))
        .ok_or_else(|| format!("Agent {agent_did} not found in DB"))?;

    def.operator_key_seed = stored.operator_key_seed;
    def.agent_did = stored.agent_did.clone();
    def.created_at = stored.created_at.clone();
    def.published_to = stored.published_to.clone();
    def.updated_at = chrono::Utc::now().to_rfc3339();

    if let Some(ref ep) = def.endpoint {
        if !pap_agents::is_safe_url(&ep.url_template) {
            return Err(format!(
                "Endpoint URL failed safety check: {}",
                ep.url_template
            ));
        }
    }

    state
        .db
        .update_agent(&def)
        .map_err(|e| format!("Failed to update agent in DB: {e}"))?;

    Ok(def_to_agent_info(&def))
}

/// Generate a DynamicAgentDef from a natural-language prompt.
/// Returns a preview — the agent is NOT yet saved.
#[tauri::command]
pub async fn generate_agent(
    state: tauri::State<'_, AppState>,
    prompt: String,
) -> Result<DynamicAgentDef, String> {
    // Read LLM provider from orchestrator config
    let provider = state
        .orchestrator_config
        .read()
        .map_err(|e| format!("orchestrator_config lock poisoned: {e}"))?
        .clone()
        .inference_substrate;

    // BuiltIn provider cannot issue HTTP chat completions
    if matches!(provider, papillon_shared::LlmProvider::BuiltIn { .. }) {
        return Err(
            "BuiltIn provider cannot be used for agent generation — configure an HTTP LLM provider"
                .into(),
        );
    }

    const SYSTEM_PROMPT: &str = concat!(
        "You are a PAP protocol agent definition generator. ",
        "Produce a valid DynamicAgentDef JSON object from the user's description. ",
        "Rules: ",
        "1. Use schema.org action types for the action field (e.g. \"schema:SearchAction\"). ",
        "2. Prefer zero-auth public HTTPS APIs for endpoint.url_template. ",
        "3. endpoint.url_template MUST use https:// and MUST NOT reference RFC 1918 addresses or localhost. ",
        "4. response_jsonpath MUST be valid RFC 9535 syntax. ",
        "5. schema_version must be 1. ",
        "6. Output only the JSON object — no markdown, no explanation."
    );

    let messages = vec![
        crate::commands::llm::ChatMessage {
            role: "system".into(),
            content: SYSTEM_PROMPT.into(),
        },
        crate::commands::llm::ChatMessage {
            role: "user".into(),
            content: prompt.clone(),
        },
    ];

    // First attempt
    let raw_json = crate::commands::llm::chat(&provider, &messages)
        .await
        .map_err(|e| e.to_string())?;

    let mut def: DynamicAgentDef = serde_json::from_str::<DynamicAgentDef>(&raw_json)
        .map_err(|e| format!("LLM returned invalid JSON: {e}\nRaw: {raw_json}"))?;

    // Validate schema.org action prefix — retry once if invalid
    if !def.action.starts_with("schema:") {
        let retry_prompt = format!(
            "{}\n\nValidation error: action must start with \"schema:\", got {:?}. Use a valid schema.org action type.",
            prompt, def.action
        );

        let retry_messages = vec![
            crate::commands::llm::ChatMessage {
                role: "system".into(),
                content: SYSTEM_PROMPT.into(),
            },
            crate::commands::llm::ChatMessage {
                role: "user".into(),
                content: retry_prompt,
            },
        ];

        let retry_json = crate::commands::llm::chat(&provider, &retry_messages)
            .await
            .map_err(|e| e.to_string())?;

        def = serde_json::from_str::<DynamicAgentDef>(&retry_json)
            .map_err(|e| format!("LLM returned invalid JSON: {e}\nRaw: {retry_json}"))?;

        if !def.action.starts_with("schema:") {
            return Err(format!(
                "Generated agent has invalid action {:?}",
                def.action
            ));
        }
    }

    // Validate endpoint URL safety
    if let Some(ref ep) = def.endpoint {
        if !pap_agents::is_safe_url(&ep.url_template) {
            return Err(format!(
                "Generated endpoint URL failed safety check: {}",
                ep.url_template
            ));
        }
    }

    // Strip sensitive fields before returning the preview
    if let Some(ref mut ep) = def.endpoint {
        ep.headers.clear();
    }
    def.operator_key_seed = None;
    def.agent_did = None;
    def.source = DynamicAgentSource::Generated;

    Ok(def)
}

/// Publish an agent advertisement to a remote registry URL.
/// POSTs the AgentAdvertisement JSON to `{registry_url}/api/agents` then
/// records the URL in `published_to` in the local DB.
#[tauri::command]
pub async fn publish_agent(
    state: tauri::State<'_, AppState>,
    agent_did: String,
    registry_url: String,
) -> Result<(), String> {
    // 1. Find the advertisement in the local registry.
    let ad = {
        let reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        reg.all_advertisements()
            .iter()
            .find(|a| a.provider.did == agent_did)
            .cloned()
            .ok_or_else(|| format!("No advertisement found for DID {agent_did}"))?
    };

    // 2. POST to {registry_url}/api/agents.
    let base = registry_url.trim_end_matches('/');
    let endpoint = format!("{base}/api/agents");

    let client = reqwest::Client::new();
    let response = client
        .post(&endpoint)
        .json(&ad)
        .send()
        .await
        .map_err(|e| format!("HTTP request to {endpoint} failed: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".into());
        return Err(format!(
            "Registry returned {status} for POST {endpoint}: {body}"
        ));
    }

    // 3. Load the DynamicAgentDef from DB and update published_to.
    let mut def = state
        .db
        .load_all_agents()
        .map_err(|e| format!("Failed to load agents from DB: {e}"))?
        .into_iter()
        .find(|d| d.agent_did.as_deref() == Some(agent_did.as_str()))
        .ok_or_else(|| format!("Agent {agent_did} not found in DB"))?;

    if !def.published_to.contains(&registry_url) {
        def.published_to.push(registry_url.clone());
    }
    def.updated_at = chrono::Utc::now().to_rfc3339();

    state
        .db
        .update_agent(&def)
        .map_err(|e| format!("Failed to persist published_to for {agent_did}: {e}"))?;

    Ok(())
}

/// Remove an agent advertisement from a remote registry URL.
/// Sends DELETE to `{registry_url}/api/agents/{content_hash}` then removes
/// the URL from `published_to` in the local DB.
#[tauri::command]
pub async fn unpublish_agent(
    state: tauri::State<'_, AppState>,
    agent_did: String,
    registry_url: String,
) -> Result<(), String> {
    // 1. Resolve the content hash from the local registry.
    let content_hash = {
        let reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        reg.all_advertisements()
            .iter()
            .find(|a| a.provider.did == agent_did)
            .map(|a| a.hash())
            .ok_or_else(|| format!("No advertisement found for DID {agent_did}"))?
    };

    // 2. DELETE {registry_url}/api/agents/{content_hash}.
    let base = registry_url.trim_end_matches('/');
    let endpoint = format!("{base}/api/agents/{content_hash}");

    let client = reqwest::Client::new();
    let response = client
        .delete(&endpoint)
        .send()
        .await
        .map_err(|e| format!("HTTP request to {endpoint} failed: {e}"))?;

    let status = response.status();
    if !status.is_success() && status != reqwest::StatusCode::NOT_FOUND {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable body>".into());
        return Err(format!(
            "Registry returned {status} for DELETE {endpoint}: {body}"
        ));
    }

    // 3. Load the DynamicAgentDef from DB and remove this registry_url.
    let mut def = state
        .db
        .load_all_agents()
        .map_err(|e| format!("Failed to load agents from DB: {e}"))?
        .into_iter()
        .find(|d| d.agent_did.as_deref() == Some(agent_did.as_str()))
        .ok_or_else(|| format!("Agent {agent_did} not found in DB"))?;

    def.published_to.retain(|u| u != &registry_url);
    def.updated_at = chrono::Utc::now().to_rfc3339();

    state
        .db
        .update_agent(&def)
        .map_err(|e| format!("Failed to persist published_to for {agent_did}: {e}"))?;

    Ok(())
}
