use pap_agents::{DynamicAgentDef, DynamicAgentSource};
use pap_did::{verify_key_from_did, PrincipalKeypair};
use pap_marketplace::AgentAdvertisement;
use papillon_shared::types::AgentInfo;

use crate::db::prelude::DatabaseOps;
use crate::state::AppState;

// ── Helpers ───────────────────────────────────────────────────────────────────

const LOCAL_UNPUBLISHED_SENTINEL: &str = "pap://local:unpublished";

fn source_to_str(source: &DynamicAgentSource) -> &'static str {
    match source {
        DynamicAgentSource::Catalog => "catalog",
        DynamicAgentSource::UserCreated => "user_created",
        DynamicAgentSource::Generated => "generated",
        DynamicAgentSource::Federation => "federation",
    }
}

/// Derive agent lifecycle from the `published_to` sentinel values.
fn lifecycle_from_published_to(published_to: &[String]) -> papillon_shared::AgentLifecycle {
    if published_to
        .iter()
        .any(|u| u == crate::state::LOCAL_REGISTRY_URL)
    {
        papillon_shared::AgentLifecycle::Published
    } else if published_to.iter().any(|u| u == LOCAL_UNPUBLISHED_SENTINEL) {
        papillon_shared::AgentLifecycle::Unpublished
    } else {
        papillon_shared::AgentLifecycle::Draft
    }
}

/// Convert a verified `AgentAdvertisement` into a `DynamicAgentDef` for
/// local storage.
///
/// Federation agents have no local keypair: `operator_key_seed` is `None` and
/// `source` is `DynamicAgentSource::Federation`.  The operator's DID is the
/// signing authority; this node has no authority to sign on their behalf.
fn ad_to_federation_def(ad: &AgentAdvertisement) -> DynamicAgentDef {
    let now = chrono::Utc::now().to_rfc3339();
    DynamicAgentDef {
        agent_did: Some(ad.provider.did.clone()),
        schema_version: 1,
        version: ad.version.clone(),
        name: ad.name.clone(),
        provider: ad.provider.name.clone(),
        description: String::new(),
        action: ad.capability.first().cloned().unwrap_or_default(),
        object_types: ad.object_types.clone(),
        requires_disclosure: ad.requires_disclosure.clone(),
        returns: ad.returns.clone(),
        endpoint: None,
        llm_instructions: String::new(),
        subagents: vec![],
        source: DynamicAgentSource::Federation,
        // No local keypair — the operator holds their own key.
        operator_key_seed: None,
        published_to: vec![],
        catalog_path: None,
        configurable_properties: ad.configurable_properties.clone(),
        created_at: now.clone(),
        updated_at: now,
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
        // Callers that need live=false (DB-only agents) override this after construction.
        live: true,
        category: def.category().to_string(),
        execution_target: papillon_shared::ExecutionTarget::None,
        lifecycle: lifecycle_from_published_to(&def.published_to),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// List all local agents: compiled + catalog + user_created + generated.
/// Returns AgentInfo for each. No sensitive fields.
///
/// Sources:
/// - Registry advertisements → compiled agents (no DB row) and any
///   dynamically-registered agents.
/// - DB rows with agent_did not already in the registry → catalog/user/generated
///   agents that are available but weren't loaded into the runtime registry
///   (e.g. first launch before catalog seeding completes, or production builds
///   where the catalog is pre-seeded but not re-registered yet).
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

    // Collect DIDs already covered by the registry so we can append DB-only agents below.
    let mut seen_dids: std::collections::HashSet<String> =
        ads.iter().map(|ad| ad.provider.did.clone()).collect();

    // 1. Registry ads (compiled + successfully registered dynamic agents).
    //    These are fully live — the runtime has a handler and keypair for each.
    let mut agents: Vec<AgentInfo> = ads
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
                live: true,
                category: db_def
                    .map(|d| d.category().to_string())
                    .unwrap_or_else(|| "general".to_owned()),
                execution_target: papillon_shared::ExecutionTarget::None,
                lifecycle: db_def
                    .map(|d| lifecycle_from_published_to(&d.published_to))
                    .unwrap_or(papillon_shared::AgentLifecycle::Draft),
            }
        })
        .collect();

    // 2. DB-only agents (catalog/user_created/generated agents whose advertisement
    //    didn't make it into the runtime registry — e.g. first-launch timing or
    //    registration failure). Marked live=false so the frontend knows they are
    //    not yet invocable and must not be added to the pap:// catalog index.
    for def in &db_defs {
        if let Some(did) = &def.agent_did {
            if seen_dids.insert(did.clone()) {
                let mut info = def_to_agent_info(def);
                info.live = false;
                agents.push(info);
            }
        }
    }

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

/// Sign an agent advertisement and mark it published to the local PAP registry.
/// Transitions Draft → Published (or Unpublished → Published on re-publish) by
/// adding `LOCAL_REGISTRY_URL` to `published_to` and removing any unpublished sentinel.
/// The advertisement is already signed when the agent was saved via `save_agent`.
#[tauri::command]
pub async fn sign_and_publish_local(
    state: tauri::State<'_, AppState>,
    agent_did: String,
) -> Result<AgentInfo, String> {
    let mut def = state
        .db
        .load_all_agents()
        .map_err(|e| format!("Failed to load agents: {e}"))?
        .into_iter()
        .find(|d| d.agent_did.as_deref() == Some(agent_did.as_str()))
        .ok_or_else(|| format!("Agent {agent_did} not found"))?;

    def.published_to.retain(|u| u != LOCAL_UNPUBLISHED_SENTINEL);
    if !def
        .published_to
        .iter()
        .any(|u| u == crate::state::LOCAL_REGISTRY_URL)
    {
        def.published_to
            .push(crate::state::LOCAL_REGISTRY_URL.to_string());
    }
    def.updated_at = chrono::Utc::now().to_rfc3339();

    state
        .db
        .update_agent(&def)
        .map_err(|e| format!("Failed to update agent: {e}"))?;

    Ok(def_to_agent_info(&def))
}

/// Remove an agent advertisement from the local PAP registry.
/// Transitions Published → Unpublished by replacing the `LOCAL_REGISTRY_URL` sentinel
/// with `LOCAL_UNPUBLISHED_SENTINEL` in `published_to`.
#[tauri::command]
pub async fn unpublish_local(
    state: tauri::State<'_, AppState>,
    agent_did: String,
) -> Result<AgentInfo, String> {
    let mut def = state
        .db
        .load_all_agents()
        .map_err(|e| format!("Failed to load agents: {e}"))?
        .into_iter()
        .find(|d| d.agent_did.as_deref() == Some(agent_did.as_str()))
        .ok_or_else(|| format!("Agent {agent_did} not found"))?;

    def.published_to
        .retain(|u| u != crate::state::LOCAL_REGISTRY_URL);
    if !def
        .published_to
        .iter()
        .any(|u| u == LOCAL_UNPUBLISHED_SENTINEL)
    {
        def.published_to
            .push(LOCAL_UNPUBLISHED_SENTINEL.to_string());
    }
    def.updated_at = chrono::Utc::now().to_rfc3339();

    state
        .db
        .update_agent(&def)
        .map_err(|e| format!("Failed to update agent: {e}"))?;

    Ok(def_to_agent_info(&def))
}

/// Approve a federation agent advertisement for local use.
///
/// Validates the advertisement signature, converts it into a `DynamicAgentDef`
/// with `source = Federation` and `operator_key_seed = None`, persists it to
/// the local SQLite `agents` table, and registers it in the live local registry.
///
/// After this call the agent is immediately visible to `IntentIndex` (BM25)
/// because `IntentIndex::new` is built from `state.db.load_all_agents()`.
///
/// # Errors
///
/// Returns an error string if:
/// - The advertisement has no signature.
/// - `signed_by` is not a valid `did:key` (cannot derive verifying key).
/// - The signature verification fails (tampered or wrong key).
/// - The DB insert fails.
#[tauri::command]
pub async fn approve_federation_agent(
    state: tauri::State<'_, AppState>,
    ad: AgentAdvertisement,
) -> Result<AgentInfo, String> {
    // 1. Derive verifying key from the DID embedded in the advertisement.
    let vk = verify_key_from_did(&ad.signed_by)
        .map_err(|e| format!("Cannot derive verifying key from signed_by DID: {e}"))?;

    // 2. Verify the advertisement signature.
    ad.verify(&vk)
        .map_err(|e| format!("Advertisement signature verification failed: {e}"))?;

    // 3. Convert to a local DynamicAgentDef (no keypair, source=Federation).
    let def = ad_to_federation_def(&ad);

    // 4. Persist to DB so it survives restarts and is visible to IntentIndex.
    state
        .db
        .insert_agent(&def)
        .map_err(|e| format!("Failed to persist federation agent: {e}"))?;

    // 5. Register in the live local registry for immediate invocability.
    {
        let mut reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        let _ = reg.register_local(ad);
    }

    Ok(def_to_agent_info(&def))
}

// ── TraitBeacon profile ───────────────────────────────────────────────────────

/// Save the user's advertised Trait Beacon profile (a Schema.org Person document).
///
/// Persists the profile to settings DB under `"trait_beacon_profile"`, updates
/// the in-memory `trait_beacon_profile` field on `AppState`, and pushes a
/// rebuilt personal-context preamble into the watch channel so all orchestrator
/// LLM consumers immediately reflect the updated traits.
///
/// Returns an error if `profile` does not carry `"@type": "Person"`.
#[tauri::command]
pub fn save_trait_beacon_profile(
    state: tauri::State<'_, AppState>,
    profile: serde_json::Value,
) -> Result<(), String> {
    // Validate that this is a Schema.org Person document.
    match profile.get("@type").and_then(|v| v.as_str()) {
        Some("Person") | Some("schema:Person") => {}
        other => {
            return Err(format!(
                "Trait Beacon profile must have @type 'Person', got {:?}",
                other
            ));
        }
    }

    // Persist to settings DB so it survives restarts.
    state
        .db
        .set_setting(
            "trait_beacon_profile",
            &serde_json::to_string(&profile)
                .map_err(|e| format!("Failed to serialize profile: {e}"))?,
        )
        .map_err(|e| format!("Failed to persist trait beacon profile: {e}"))?;

    // Update in-memory Arc so the next context rebuild picks it up.
    if let Ok(mut guard) = state.trait_beacon_profile.write() {
        *guard = profile.clone();
    }

    // Rebuild and broadcast the personal context preamble.
    {
        use papillon_shared::PersonalContext;
        let preamble = PersonalContext::from_db(&*state.db, Some(profile)).to_system_preamble();
        let _ = state.context_tx.send(preamble);
    }

    Ok(())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pap_did::PrincipalKeypair;
    use pap_marketplace::AgentAdvertisement;

    fn make_signed_ad(name: &str, action: &str) -> (AgentAdvertisement, PrincipalKeypair) {
        let kp = PrincipalKeypair::generate();
        let mut ad = AgentAdvertisement::new(
            name,
            "Test Provider",
            kp.did(),
            vec![action.to_string()],
            vec!["schema:Thing".to_string()],
            vec![],
            vec!["schema:Result".to_string()],
        );
        ad.signed_by = kp.did();
        ad.sign(kp.signing_key()).expect("Ed25519 always works");
        (ad, kp)
    }

    #[test]
    fn source_to_str_covers_all_variants() {
        assert_eq!(source_to_str(&DynamicAgentSource::Catalog), "catalog");
        assert_eq!(
            source_to_str(&DynamicAgentSource::UserCreated),
            "user_created"
        );
        assert_eq!(source_to_str(&DynamicAgentSource::Generated), "generated");
        assert_eq!(source_to_str(&DynamicAgentSource::Federation), "federation");
    }

    #[test]
    fn ad_to_federation_def_sets_federation_source() {
        let (ad, _kp) = make_signed_ad("Weather Agent", "schema:CheckAction");
        let def = ad_to_federation_def(&ad);
        assert_eq!(def.source, DynamicAgentSource::Federation);
    }

    #[test]
    fn ad_to_federation_def_has_no_keypair() {
        let (ad, _kp) = make_signed_ad("Search Agent", "schema:SearchAction");
        let def = ad_to_federation_def(&ad);
        assert!(
            def.operator_key_seed.is_none(),
            "federation agent must have no local keypair"
        );
    }

    #[test]
    fn ad_to_federation_def_preserves_action_and_did() {
        let (ad, kp) = make_signed_ad("Hotel Agent", "schema:ReserveAction");
        let def = ad_to_federation_def(&ad);
        assert_eq!(def.action, "schema:ReserveAction");
        assert_eq!(def.agent_did.as_deref(), Some(kp.did().as_str()));
    }

    #[test]
    fn ad_to_federation_def_preserves_capability_fields() {
        let (ad, _kp) = make_signed_ad("Geo Agent", "schema:FindAction");
        let def = ad_to_federation_def(&ad);
        assert_eq!(def.object_types, vec!["schema:Thing"]);
        assert_eq!(def.returns, vec!["schema:Result"]);
        assert!(def.requires_disclosure.is_empty());
    }

    #[test]
    fn verify_key_from_did_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let vk = verify_key_from_did(&kp.did()).expect("valid did:key");
        assert_eq!(vk.as_bytes(), kp.verifying_key().as_bytes());
    }

    /// After `ad_to_federation_def()` the resulting `DynamicAgentDef` must be
    /// immediately visible to `IntentIndex` (BM25).  This is the core invariant
    /// that closes the federation-agent BM25 gap: an approved remote agent is
    /// indistinguishable from a local catalog agent from the router's perspective.
    #[test]
    fn approved_federation_def_is_visible_to_bm25() {
        use pap_agents::IntentIndex;

        let kp = PrincipalKeypair::generate();
        let mut ad = AgentAdvertisement::new(
            "FedWeather",
            "Fed Provider",
            kp.did(),
            vec!["schema:CheckAction".to_string()],
            vec!["schema:Place".to_string()],
            vec![],
            vec!["schema:WeatherForecast".to_string()],
        );
        ad.signed_by = kp.did();
        ad.sign(kp.signing_key()).expect("Ed25519 always works");

        let mut def = ad_to_federation_def(&ad);
        // Give the def a rich description so BM25 has tokens to score.
        def.description =
            "Real-time weather forecast temperature humidity wind conditions any location."
                .to_string();
        def.llm_instructions =
            "You are a weather assistant. weather temperature forecast.".to_string();

        let catalog = vec![def];
        let index = IntentIndex::new(&catalog);
        let m = index
            .classify("weather in Tokyo", 0.25)
            .expect("federation agent must appear in BM25 index");
        assert_eq!(m.agent_name.as_deref(), Some("FedWeather"));
        assert_eq!(m.action, "schema:CheckAction");
    }

    #[test]
    fn lifecycle_empty_is_draft() {
        assert_eq!(
            lifecycle_from_published_to(&[]),
            papillon_shared::AgentLifecycle::Draft
        );
    }

    #[test]
    fn lifecycle_local_sentinel_is_published() {
        let v = vec![crate::state::LOCAL_REGISTRY_URL.to_string()];
        assert_eq!(
            lifecycle_from_published_to(&v),
            papillon_shared::AgentLifecycle::Published
        );
    }

    #[test]
    fn lifecycle_unpublished_sentinel_is_unpublished() {
        let v = vec![LOCAL_UNPUBLISHED_SENTINEL.to_string()];
        assert_eq!(
            lifecycle_from_published_to(&v),
            papillon_shared::AgentLifecycle::Unpublished
        );
    }

    #[test]
    fn lifecycle_remote_url_only_is_draft() {
        let v = vec!["https://registry.example.com".to_string()];
        assert_eq!(
            lifecycle_from_published_to(&v),
            papillon_shared::AgentLifecycle::Draft
        );
    }

    #[test]
    fn lifecycle_published_takes_precedence() {
        // If somehow both sentinels are present, Published wins.
        let v = vec![
            crate::state::LOCAL_REGISTRY_URL.to_string(),
            LOCAL_UNPUBLISHED_SENTINEL.to_string(),
        ];
        assert_eq!(
            lifecycle_from_published_to(&v),
            papillon_shared::AgentLifecycle::Published
        );
    }
}
