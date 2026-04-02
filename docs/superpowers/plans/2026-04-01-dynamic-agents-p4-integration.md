# Dynamic Agents — Part 4: Integration (startup, commands, federation)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire up catalog seeding at startup, add Tauri commands for agent lifecycle management, and add advertisement rate limiting to Chrysalis.

**Architecture:** AppState::with_db() gains a catalog-seeding step after build_agents(). New commands/agents.rs exposes 7 Tauri commands. Chrysalis POST /api/agents checks a per-principal count before accepting.

**Tech Stack:** Rust, Tauri, rusqlite, pap-agents catalog loader, pap-federation

---

## Context and dependencies

This is Part 4 of 4. It assumes Parts 1–3 are merged:

- **Part 1** — `DynamicAgentDef`, `HttpEndpointConfig`, `DynamicAgentHandler` in `crates/pap-agents/src/dynamic.rs`
- **Part 2** — `AgentSet::register_dynamic()` in `crates/pap-agents/src/registry.rs`; catalog TOML loader (`pap_agents::load_catalog`)
- **Part 3** — DB migration `0002_agents.sql`; `Database::insert_agent`, `load_all_agents`, `delete_agent`, `update_agent` in `crates/papillon-shared/src/db/`

Import paths used throughout:
- `pap_agents::{DynamicAgentDef, load_catalog}`
- `pap_did::PrincipalKeypair`
- `papillon_shared::types::AgentInfo`
- `crate::db::prelude::DatabaseOps`
- `crate::state::AppState`

---

## Task 8: Startup catalog seeding in AppState

**Files:**
- Modify: `apps/papillon/src/state.rs`
- Modify: `apps/papillon/src/lib.rs` (pass catalog dir to `with_db`)

### Step 8.1 — Extend `with_db` signature

- [ ] Change `with_db(db: Arc<Database>, profiles_db: Arc<ProfilesDatabase>)` to
  `with_db(db: Arc<Database>, profiles_db: Arc<ProfilesDatabase>, catalog_dir: PathBuf)`.
- [ ] Update every call site: `AppState::new()`, `AppState::default()`, and the test helper
  `make_app_state()` in `state.rs`.
  - In `AppState::new()`: pass `PathBuf::new()` as a placeholder — the real path is set by
    `lib.rs` (see Step 8.2).
  - In `AppState::default()`: pass `PathBuf::new()` (no catalog in fallback mode).
  - In `make_app_state()` (test helper): pass
    `PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog")` so tests can exercise the
    seeding path against the real catalog directory.

### Step 8.2 — Resolve catalog dir in `lib.rs`

- [ ] In `lib.rs`'s `run()`, immediately after resolving `resource_dir`, derive `catalog_dir`:

```rust
let catalog_dir = resource_dir.join("catalog");
```

- [ ] Pass `catalog_dir` to `AppState::new(&db_path)` — adjust `AppState::new` to accept it and
  thread it through to `with_db`.

### Step 8.3 — Catalog seeding block inside `with_db`

Insert the following block inside `with_db`, **after** `let agent_set = build_agents(extra);`
and **before** the `SocialDiscoveryAgent` / `TraitBeaconAgent` construction:

```rust
// ── Catalog seeding (first startup + upgrade detection) ──────────────────
if catalog_dir.exists() {
    let catalog_defs = pap_agents::load_catalog(&catalog_dir);
    let existing_agents = db.load_all_agents().unwrap_or_default();
    let existing_catalog_paths: std::collections::HashSet<String> = existing_agents
        .iter()
        .filter_map(|a| a.catalog_path.as_deref())
        .map(str::to_owned)
        .collect();

    for mut def in catalog_defs {
        if def.catalog_path.as_deref()
            .map(|p| existing_catalog_paths.contains(p))
            .unwrap_or(false)
        {
            continue; // already seeded
        }
        let kp = PrincipalKeypair::generate();
        def.operator_key_seed = Some(kp.signing_key().to_bytes());
        def.agent_did = Some(kp.did());
        let now = chrono::Utc::now().to_rfc3339();
        def.created_at = now.clone();
        def.updated_at = now;
        if let Err(e) = db.insert_agent(&def) {
            eprintln!("Failed to seed catalog agent '{}': {e}", def.name);
            continue;
        }
    }
}
```

Note: `catalog_path` is a field added to `DynamicAgentDef` in Part 2 (set from the TOML
file's relative path within the catalog directory, e.g. `"search/duckduckgo.toml"`).

### Step 8.4 — Load all DB agents and register them live

Immediately after the catalog seeding block (still before Social/Trait agent construction):

```rust
// ── Register all DB agents (catalog + user_created + generated) ───────────
{
    let orchestrator_config = OrchestratorConfig::default();
    let llm_provider = Arc::new(orchestrator_config.llm_provider.clone());
    let db_agents = db.load_all_agents().unwrap_or_default();
    for def in db_agents {
        if let Err(e) = agent_set.register_dynamic(&def, llm_provider.clone()) {
            eprintln!("Failed to register agent '{}': {e}", def.name);
        }
    }
}
```

Import `OrchestratorConfig` — it is already available via `use papillon_shared::OrchestratorConfig`
which is already present at the top of `state.rs`.

### Step 8.5 — Update `local_registry_contains_all_agents` test

- [ ] Replace the hardcoded count assertion with a floor assertion:

```rust
#[test]
fn local_registry_contains_all_agents() {
    let state = make_app_state();
    let registry = state.local_registry.lock().unwrap();
    let ads = registry.all_advertisements();

    // Minimum: 1 WebReader (compiled) + catalog entries + OnDeviceAI + Social Discovery
    // + Trait Beacon. Catalog grows, so assert a floor rather than an exact count.
    assert!(
        ads.len() >= 5,
        "Expected at least 5 agents in local_registry, got {}. Names: {:?}",
        ads.len(),
        ads.iter().map(|a| &a.name).collect::<Vec<_>>()
    );
}
```

The existing tests `social_discovery_registered_with_correct_metadata`,
`trait_beacon_registered_with_correct_metadata`, `app_specific_agents_have_handlers`,
`app_specific_agents_have_keypairs`, `all_handlers_have_matching_keypairs`,
`all_handlers_have_matching_advertisements`, and `local_registry_bookmarks_include_local`
require no changes.

### Step 8.6 — Run and commit

- [ ] `cargo test -p papillon -- state::` — expected: all pass
- [ ] Commit: `feat(papillon): seed catalog agents at startup`

---

## Task 9: AgentInfo type extension + Tauri commands

### Step 9.1 — Extend `AgentInfo` in `papillon-shared`

**File:** `crates/papillon-shared/src/types.rs`

Replace the current `AgentInfo` struct with the extended version:

```rust
/// Agent information for display in the registry browser and agent management UI.
/// This is the safe frontend-facing type — never contains operator_key_seed,
/// HttpEndpointConfig, llm_instructions, or description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub provider_name: String,
    pub provider_did: String,
    pub capabilities: Vec<String>,
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    pub endpoint: Option<String>,
    pub content_hash: String,
    /// The agent's DID (did:key:z...). None for advertisements where DID is
    /// embedded in the provider field only.
    pub agent_did: Option<String>,
    /// Origin of this agent: "compiled", "catalog", "user_created", or "generated".
    pub source: String,
    /// Registry URLs this agent's advertisement has been POSTed to.
    pub published_to: Vec<String>,
}
```

The three new fields (`agent_did`, `source`, `published_to`) default naturally to `None`,
`""`, and `[]` via `Option`/`Vec`. No `#[serde(default)]` annotation is needed for new
serialization — all three fields are present on every new `AgentInfo`. Existing callers
that construct `AgentInfo` (in `commands/registry.rs`) must be updated to supply values for
the three new fields (see Step 9.3).

- [ ] Audit `commands/registry.rs` for any `AgentInfo { .. }` construction and fill in the
  three new fields with sensible defaults (`agent_did: None`, `source: "compiled".into()`,
  `published_to: vec![]`) where not otherwise derivable.

### Step 9.2 — Create `apps/papillon/src/commands/agents.rs`

Create the file with all 7 commands. Complete code for each command follows.

```rust
use std::sync::Arc;

use pap_agents::DynamicAgentDef;
use pap_did::PrincipalKeypair;
use papillon_shared::types::AgentInfo;

use crate::state::AppState;
use crate::db::prelude::DatabaseOps;

// ── Helper ────────────────────────────────────────────────────────────────────

/// Convert a DynamicAgentDef into the safe frontend-facing AgentInfo.
/// Strips operator_key_seed, HttpEndpointConfig, llm_instructions, description.
fn def_to_agent_info(def: &DynamicAgentDef) -> AgentInfo {
    AgentInfo {
        name: def.name.clone(),
        provider_name: def.provider.clone(),
        provider_did: def.agent_did.clone().unwrap_or_default(),
        capabilities: def.action.clone().into_iter().collect(),
        object_types: def.object_types.clone(),
        requires_disclosure: def.requires_disclosure.clone(),
        returns: def.returns.clone(),
        endpoint: None, // endpoint URL is internal; never forwarded to the frontend
        content_hash: String::new(), // computed after advertisement signing
        agent_did: def.agent_did.clone(),
        source: def.source.as_str().to_owned(),
        published_to: def.published_to.clone(),
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// Generate a DynamicAgentDef from a natural-language prompt using the
/// configured LLM provider. Returns a preview — the agent is NOT yet saved.
/// HttpEndpointConfig.headers are stripped before the struct is returned.
#[tauri::command]
pub async fn generate_agent(
    state: tauri::State<'_, AppState>,
    prompt: String,
) -> Result<DynamicAgentDef, String> {
    let llm_provider = {
        let config = state.orchestrator_config.read().unwrap();
        Arc::new(config.llm_provider.clone())
    };

    let system_prompt = "\
You are a PAP protocol agent definition generator. \
Produce a valid DynamicAgentDef JSON object from the user's description. \
Rules: \
1. Use schema.org action types for the `action` field (e.g. \"schema:SearchAction\"). \
2. Prefer zero-auth public HTTPS APIs for `endpoint.url_template`. \
3. `endpoint.url_template` MUST use https:// and MUST NOT reference RFC 1918 addresses or localhost. \
4. `response_jsonpath` MUST be valid RFC 9535 syntax. \
5. `schema_version` must be 1. \
6. Output only the JSON object — no markdown, no explanation.";

    let raw_json = crate::inference::llm_chat(
        &llm_provider,
        system_prompt,
        &prompt,
        state.model_manager.clone(),
    )
    .await
    .map_err(|e| format!("LLM generation failed: {e}"))?;

    let mut def: DynamicAgentDef = serde_json::from_str(&raw_json)
        .map_err(|e| format!("LLM returned invalid JSON: {e}\nRaw output: {raw_json}"))?;

    // Validate schema.org action
    if !def.action.starts_with("schema:") {
        // Retry once with error appended
        let retry_prompt = format!(
            "{prompt}\n\nValidation error: `action` must start with \"schema:\", got {:?}. \
             Use a valid schema.org action type.",
            def.action
        );
        let raw_json2 = crate::inference::llm_chat(
            &llm_provider,
            system_prompt,
            &retry_prompt,
            state.model_manager.clone(),
        )
        .await
        .map_err(|e| format!("LLM retry failed: {e}"))?;
        def = serde_json::from_str(&raw_json2)
            .map_err(|e| format!("LLM retry returned invalid JSON: {e}"))?;
        if !def.action.starts_with("schema:") {
            return Err(format!(
                "Generated agent has invalid action {:?} — must be a schema.org type",
                def.action
            ));
        }
    }

    // Validate URL safety if endpoint present
    if let Some(ref ep) = def.endpoint {
        pap_agents::validate_url_safety(&ep.url_template)
            .map_err(|e| format!("Generated endpoint URL failed safety check: {e}"))?;
    }

    // Strip headers (API keys) before returning to frontend
    if let Some(ref mut ep) = def.endpoint {
        ep.headers.clear();
    }

    // Do NOT set operator_key_seed or agent_did — these are set at save time
    def.operator_key_seed = None;
    def.agent_did = None;
    def.source = pap_agents::DynamicAgentSource::Generated;

    Ok(def)
}

/// Atomically save a dynamic agent: generate keypair → sign advertisement →
/// insert into DB → register live in agent_set. Returns AgentInfo (no sensitive fields).
#[tauri::command]
pub async fn save_agent(
    state: tauri::State<'_, AppState>,
    mut def: DynamicAgentDef,
) -> Result<AgentInfo, String> {
    // Generate operator keypair and derive DID
    let kp = PrincipalKeypair::generate();
    let agent_did = kp.did();
    def.operator_key_seed = Some(kp.signing_key().to_bytes());
    def.agent_did = Some(agent_did.clone());

    let now = chrono::Utc::now().to_rfc3339();
    def.created_at = now.clone();
    def.updated_at = now;

    // URL safety check (defense in depth — also checked at generate time)
    if let Some(ref ep) = def.endpoint {
        pap_agents::validate_url_safety(&ep.url_template)
            .map_err(|e| format!("Endpoint URL failed safety check: {e}"))?;
        if matches!(ep.method, pap_agents::HttpMethod::Get)
            && ep.body_template.is_some()
        {
            return Err("body_template must be None for GET requests".into());
        }
    }

    // Persist first — never leave an unsigned intermediate state
    state
        .db
        .insert_agent(&def)
        .map_err(|e| format!("Failed to persist agent: {e}"))?;

    // Register live — agent is queryable immediately after this call
    let llm_provider = {
        let config = state.orchestrator_config.read().unwrap();
        Arc::new(config.llm_provider.clone())
    };
    {
        // agent_set is not in AppState today; registration goes through local_registry + keypairs.
        // When AgentSet is added to AppState (Part 2 scope), replace the block below.
        let kp_for_ad = PrincipalKeypair::from_bytes(
            &def.operator_key_seed.ok_or("operator_key_seed missing after set")?,
        )
        .map_err(|e| format!("Failed to reconstruct keypair: {e}"))?;

        let mut ad = pap_marketplace::AgentAdvertisement::new(
            &def.name,
            &def.provider,
            &agent_did,
            def.action.clone().into_iter().collect(),
            def.object_types.clone(),
            def.requires_disclosure.clone(),
            def.returns.clone(),
        );
        ad.sign(kp_for_ad.signing_key());

        {
            let mut reg = state
                .local_registry
                .lock()
                .map_err(|e| format!("Registry lock poisoned: {e}"))?;
            reg.register_local(ad)
                .map_err(|e| format!("Failed to register agent in local registry: {e}"))?;
        }

        let mut keypairs = state
            .agent_keypairs
            .write()
            .map_err(|e| format!("Keypair lock poisoned: {e}"))?;
        keypairs.insert(def.name.clone(), kp_for_ad);
    }

    let mut info = def_to_agent_info(&def);
    // Compute content_hash from the live advertisement
    {
        let reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        if let Some(ad) = reg
            .all_advertisements()
            .iter()
            .find(|a| a.provider.did == agent_did)
        {
            info.content_hash = ad.hash();
        }
    }

    Ok(info)
}

/// List all agents: compiled + catalog + user_created + generated.
/// Returns AgentInfo for each. No sensitive fields (no HttpEndpointConfig,
/// no llm_instructions, no operator_key_seed).
#[tauri::command]
pub async fn list_agents(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<AgentInfo>, String> {
    let registry = state
        .local_registry
        .lock()
        .map_err(|e| format!("Registry lock poisoned: {e}"))?;

    let ads = registry.all_advertisements();

    // Load DB defs so we can fill in `source` and `published_to`
    let db_defs = state.db.load_all_agents().unwrap_or_default();

    let agents: Vec<AgentInfo> = ads
        .iter()
        .map(|ad| {
            // Match by DID to find the corresponding DynamicAgentDef (if any)
            let db_def = db_defs.iter().find(|d| {
                d.agent_did.as_deref() == Some(ad.provider.did.as_str())
            });

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
                    .map(|d| d.source.as_str().to_owned())
                    .unwrap_or_else(|| "compiled".to_owned()),
                published_to: db_def
                    .map(|d| d.published_to.clone())
                    .unwrap_or_default(),
            }
        })
        .collect();

    Ok(agents)
}

/// Delete a DB agent (catalog, user_created, or generated) by DID.
/// Compiled agents cannot be deleted. Does NOT auto-unpublish from federation
/// registries — call `unpublish_agent` first if needed.
#[tauri::command]
pub async fn delete_agent(
    state: tauri::State<'_, AppState>,
    agent_did: String,
) -> Result<(), String> {
    // Remove from DB
    state
        .db
        .delete_agent(&agent_did)
        .map_err(|e| format!("Failed to delete agent from DB: {e}"))?;

    // Remove from in-memory local_registry by DID
    {
        let mut reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        // FederatedRegistry exposes remove_by_did() (added in Part 2 scope).
        // If not yet present, fall back to finding the hash and calling remove_by_hash.
        let hash_opt = reg
            .all_advertisements()
            .iter()
            .find(|a| a.provider.did == agent_did)
            .map(|a| a.hash());
        if let Some(hash) = hash_opt {
            reg.remove_by_hash(&hash);
        }
    }

    // Remove keypair — name lookup via DID requires iterating keypairs
    {
        let mut keypairs = state
            .agent_keypairs
            .write()
            .map_err(|e| format!("Keypair lock poisoned: {e}"))?;
        keypairs.retain(|_name, kp| kp.did() != agent_did);
    }

    Ok(())
}

/// Publish an agent's AgentAdvertisement to a remote Chrysalis registry.
/// Only the advertisement is sent — DynamicAgentDef fields never leave the device.
/// Updates `published_to` in the local DB on success.
#[tauri::command]
pub async fn publish_agent(
    state: tauri::State<'_, AppState>,
    agent_did: String,
    registry_url: String,
) -> Result<(), String> {
    // Retrieve the advertisement from the local registry
    let ad = {
        let reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        reg.all_advertisements()
            .into_iter()
            .find(|a| a.provider.did == agent_did)
            .ok_or_else(|| format!("Agent {agent_did} not found in local registry"))?
            .clone()
    };

    // POST the advertisement to the remote registry
    let post_url = format!("{}/api/agents", registry_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client
        .post(&post_url)
        .json(&ad)
        .send()
        .await
        .map_err(|e| format!("Failed to POST advertisement to {post_url}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Registry rejected advertisement: HTTP {status} — {body}"));
    }

    // Update published_to in DB
    state
        .db
        .add_published_to(&agent_did, &registry_url)
        .map_err(|e| format!("Failed to update published_to in DB: {e}"))?;

    Ok(())
}

/// Remove a previously published advertisement from a remote Chrysalis registry.
/// Updates `published_to` in the local DB on success.
#[tauri::command]
pub async fn unpublish_agent(
    state: tauri::State<'_, AppState>,
    agent_did: String,
    registry_url: String,
) -> Result<(), String> {
    // Retrieve the content hash from the local registry
    let content_hash = {
        let reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        reg.all_advertisements()
            .into_iter()
            .find(|a| a.provider.did == agent_did)
            .map(|a| a.hash())
            .ok_or_else(|| format!("Agent {agent_did} not found in local registry"))?
    };

    // DELETE from the remote registry
    let delete_url = format!(
        "{}/api/agents/{}",
        registry_url.trim_end_matches('/'),
        content_hash
    );
    let client = reqwest::Client::new();
    let resp = client
        .delete(&delete_url)
        .send()
        .await
        .map_err(|e| format!("Failed to DELETE advertisement at {delete_url}: {e}"))?;

    if !resp.status().is_success() && resp.status() != reqwest::StatusCode::NOT_FOUND {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Registry rejected DELETE: HTTP {status} — {body}"));
    }

    // Update published_to in DB
    state
        .db
        .remove_published_to(&agent_did, &registry_url)
        .map_err(|e| format!("Failed to update published_to in DB: {e}"))?;

    Ok(())
}

/// Update a dynamic agent definition. Re-signs the advertisement if any
/// capability fields changed. Re-publishes to all URLs in published_to.
/// Does NOT regenerate the operator keypair — DID stability is preserved.
/// Returns AgentInfo (no sensitive fields).
#[tauri::command]
pub async fn update_agent(
    state: tauri::State<'_, AppState>,
    mut def: DynamicAgentDef,
) -> Result<AgentInfo, String> {
    let agent_did = def
        .agent_did
        .clone()
        .ok_or("update_agent: agent_did must be set")?;

    // Reload operator_key_seed from DB (never trust frontend-supplied seed)
    let stored = state
        .db
        .load_agent(&agent_did)
        .map_err(|e| format!("Failed to load agent from DB: {e}"))?
        .ok_or_else(|| format!("Agent {agent_did} not found in DB"))?;

    // Preserve immutable fields from the stored record
    def.operator_key_seed = stored.operator_key_seed;
    def.agent_did = stored.agent_did.clone();
    def.created_at = stored.created_at.clone();
    def.published_to = stored.published_to.clone();
    def.updated_at = chrono::Utc::now().to_rfc3339();

    // URL safety
    if let Some(ref ep) = def.endpoint {
        pap_agents::validate_url_safety(&ep.url_template)
            .map_err(|e| format!("Endpoint URL failed safety check: {e}"))?;
    }

    // Persist updated def
    state
        .db
        .update_agent(&def)
        .map_err(|e| format!("Failed to update agent in DB: {e}"))?;

    // Re-sign advertisement with operator keypair
    let kp = PrincipalKeypair::from_bytes(
        &def.operator_key_seed.ok_or("operator_key_seed missing")?,
    )
    .map_err(|e| format!("Failed to reconstruct keypair: {e}"))?;

    let mut ad = pap_marketplace::AgentAdvertisement::new(
        &def.name,
        &def.provider,
        &agent_did,
        def.action.clone().into_iter().collect(),
        def.object_types.clone(),
        def.requires_disclosure.clone(),
        def.returns.clone(),
    );
    ad.sign(kp.signing_key());

    // Replace in local_registry
    {
        let mut reg = state
            .local_registry
            .lock()
            .map_err(|e| format!("Registry lock poisoned: {e}"))?;
        let old_hash_opt = reg
            .all_advertisements()
            .iter()
            .find(|a| a.provider.did == agent_did)
            .map(|a| a.hash());
        if let Some(old_hash) = old_hash_opt {
            reg.remove_by_hash(&old_hash);
        }
        reg.register_local(ad.clone())
            .map_err(|e| format!("Failed to re-register agent: {e}"))?;
    }

    // Re-publish to all federation registries where it was previously published
    let published_to = def.published_to.clone();
    let client = reqwest::Client::new();
    for registry_url in &published_to {
        let post_url = format!("{}/api/agents", registry_url.trim_end_matches('/'));
        if let Err(e) = client.post(&post_url).json(&ad).send().await {
            eprintln!(
                "Warning: failed to re-publish agent '{}' to {registry_url}: {e}",
                def.name
            );
            // Non-fatal — local state is already updated; operator can retry via publish_agent
        }
    }

    let mut info = def_to_agent_info(&def);
    info.content_hash = ad.hash();

    Ok(info)
}
```

**Notes on implementation correctness:**

- `def.action` is `String` in the current `DynamicAgentDef`. The `AgentAdvertisement::new`
  call needs `Vec<String>` for capabilities. Use `vec![def.action.clone()]` — adjust if the
  type is changed to `Vec<String>` in Part 1.
- `pap_marketplace` is the crate providing `AgentAdvertisement`. It is already a dependency
  of `papillon` via `pap-agents`.
- `crate::inference::llm_chat` is a helper that needs to be added to `inference.rs` in Part 3
  (or add it here if not already present) — signature:
  `pub async fn llm_chat(provider: &LlmProvider, system: &str, user: &str, mm: Arc<tokio::sync::Mutex<ModelManager>>) -> Result<String, String>`
- `DatabaseOps` must expose: `insert_agent`, `load_all_agents`, `delete_agent`,
  `update_agent`, `load_agent`, `add_published_to`, `remove_published_to` — these are
  specified in Part 3.
- `pap_agents::validate_url_safety` is exposed from the `pap-agents` crate (Part 1 scope).
- `pap_agents::DynamicAgentSource::as_str()` must be implemented in Part 1.

### Step 9.3 — Register new module in `commands/mod.rs`

**File:** `apps/papillon/src/commands/mod.rs`

Diff:
```
 pub mod canvas;
 pub mod health;
 pub mod identity;
 pub mod llm;
 pub mod orchestrator;
 pub mod pipeline;
 pub mod profiles;
 pub mod registry;
 pub mod templates;
+pub mod agents;
```

### Step 9.4 — Register commands in `lib.rs`

**File:** `apps/papillon/src/lib.rs`

In the `invoke_handler!` macro, append after the last `commands::templates::` entry:

```rust
            commands::agents::generate_agent,
            commands::agents::save_agent,
            commands::agents::list_agents,
            commands::agents::delete_agent,
            commands::agents::publish_agent,
            commands::agents::unpublish_agent,
            commands::agents::update_agent,
```

The existing `commands::registry::list_agents` command is the registry-browser command
(lists agents from any bookmarked registry). The new `commands::agents::list_agents`
lists agents from the local node only for the management UI. Both coexist without conflict
because Tauri resolves commands by their module-qualified path in `generate_handler!`.

### Step 9.5 — Run and commit

- [ ] `cargo build -p papillon` — expected: compiles without errors
- [ ] Commit: `feat(papillon): add agent lifecycle Tauri commands`

---

## Task 10: Federation rate limiting in Chrysalis

**File:** `apps/registry/src/routes/admin.rs` — modify `register_agent` function.
**File:** `apps/registry/src/config.rs` — add `max_ads_per_principal` field.
**File:** `apps/registry/src/state.rs` — add `max_ads_per_principal` to `AppState`.

### Step 10.1 — Add `max_ads_per_principal` to `Config`

**File:** `apps/registry/src/config.rs`

In `Config` struct, add:

```rust
    /// Maximum number of advertisements accepted from a single principal DID.
    /// Enforced at POST /api/agents. Configurable via PAP_REGISTRY_MAX_ADS_PER_PRINCIPAL.
    /// Default: 100.
    pub max_ads_per_principal: usize,
```

In `Config::from_env()`, add:

```rust
        let max_ads_per_principal: usize = env::var("PAP_REGISTRY_MAX_ADS_PER_PRINCIPAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);
```

And include it in the returned `Self { .. }` initializer:

```rust
            max_ads_per_principal,
```

### Step 10.2 — Thread `max_ads_per_principal` through `AppState`

**File:** `apps/registry/src/state.rs`

In `AppState` struct, add:

```rust
    pub max_ads_per_principal: usize,
```

In `AppState::new()`, add to the initializer:

```rust
            max_ads_per_principal: config.max_ads_per_principal,
```

In `AppState::new()`'s parameter list, `config: &Config` is already present — no signature
change needed.

### Step 10.3 — Add `count_agents_by_principal` to `RegistryStore`

**File:** `apps/registry/src/db/mod.rs`

Add to the `RegistryStore` enum's `impl` block:

```rust
    pub async fn count_agents_by_principal(&self, signed_by: &str) -> Result<i64> {
        match self {
            RegistryStore::Sqlite(s) => s.count_agents_by_principal(signed_by).await,
            RegistryStore::Postgres(p) => p.count_agents_by_principal(signed_by).await,
        }
    }
```

**File:** `apps/registry/src/db/sqlite.rs`

Add to `SqliteStore`:

```rust
    pub async fn count_agents_by_principal(&self, signed_by: &str) -> Result<i64> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM agents WHERE signed_by = ?",
            signed_by
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }
```

**File:** `apps/registry/src/db/postgres.rs`

Add to `PostgresStore`:

```rust
    pub async fn count_agents_by_principal(&self, signed_by: &str) -> Result<i64> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM agents WHERE signed_by = $1",
            signed_by
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }
```

Note: `signed_by` is the `provider.did` field from `AgentAdvertisement`, which corresponds
to the `signed_by` column in the `agents` table. Verify the column name matches the
existing schema migration in `src/db/migrations/sqlite/`. If the column is named
differently (e.g. `provider_did`), use the correct name.

### Step 10.4 — Add rate limit check to `register_agent`

**File:** `apps/registry/src/routes/admin.rs`

Current `register_agent` function (lines 181–218):

```rust
async fn register_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(ad): Json<AgentAdvertisement>,
) -> Response {
    if !state.is_authorized(extract_bearer(&headers)) {
        return auth_error();
    }
    // Verify Ed25519 signature before storing.
    {
        let registry = state.registry.lock().unwrap_or_else(|e| e.into_inner());
        if !registry.verify_advertisement(&ad) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "invalid or missing Ed25519 signature — signed_by DID must match the signature"})),
            )
                .into_response();
        }
    }
    // DB first — persist before updating in-memory state.
    let hash = ad.hash();
    if let Err(e) = state.store.insert_agent(&hash, &ad).await {
        ...
    }
    ...
}
```

Add the rate limit check **after** signature verification and **before** the DB insert:

```rust
    // Per-principal advertisement count limit (spec §10.1, elevated to MUST).
    let principal_did = ad.signed_by.clone();  // or ad.provider.did — use the correct field name
    match state.store.count_agents_by_principal(&principal_did).await {
        Ok(count) if count >= state.max_ads_per_principal as i64 => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": format!(
                        "Principal {} has reached the advertisement limit of {}",
                        principal_did, state.max_ads_per_principal
                    )
                })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Rate limit check failed: {e}")})),
            )
                .into_response();
        }
        Ok(_) => {} // under limit — proceed
    }
```

Note: `StatusCode::TOO_MANY_REQUESTS` is HTTP 429. Verify this variant exists in the version
of `axum::http` used — it is present in `http` crate >= 0.2.6, which Axum depends on.

### Step 10.5 — Write the rate limit test

**File:** `apps/registry/src/routes/admin.rs` (test module at the bottom, or a new
`tests/rate_limit.rs` integration test file — prefer inline `#[cfg(test)]` mod)

```rust
#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use crate::db::{sqlite::SqliteStore, RegistryStore};
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use pap_did::PrincipalKeypair;
    use pap_marketplace::AgentAdvertisement;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt; // for `oneshot`

    async fn make_rate_limit_state(max: usize) -> AppState {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("src/db/migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        AppState {
            registry: Arc::new(Mutex::new(pap_federation::registry::FederatedRegistry::new())),
            store: Arc::new(RegistryStore::Sqlite(SqliteStore { pool })),
            node_did: "did:key:zTestNode".into(),
            node_endpoint: "https://localhost:7890".into(),
            cert_fingerprint: "sha256:test".into(),
            admin_token: None, // open for test simplicity
            max_ads_per_principal: max,
        }
    }

    fn make_ad(kp: &PrincipalKeypair, name: &str) -> AgentAdvertisement {
        let mut ad = AgentAdvertisement::new(
            name,
            "TestProvider",
            &kp.did(),
            vec!["schema:SearchAction".into()],
            vec!["schema:Thing".into()],
            vec![],
            vec!["schema:SearchResultsPage".into()],
        );
        ad.sign(kp.signing_key());
        ad
    }

    #[tokio::test]
    async fn rate_limit_rejects_101st_advertisement() {
        let state = make_rate_limit_state(100).await;
        let app = router().with_state(state.clone());

        let kp = PrincipalKeypair::generate();

        // Submit 100 advertisements — all must succeed
        for i in 0..100 {
            let ad = make_ad(&kp, &format!("Agent {i}"));
            let req = Request::builder()
                .method("POST")
                .uri("/api/agents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&ad).unwrap()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::CREATED,
                "Advertisement {i} should be accepted"
            );
        }

        // 101st advertisement from the same principal MUST be rejected with 429
        let ad_101 = make_ad(&kp, "Agent 100");
        let req = Request::builder()
            .method("POST")
            .uri("/api/agents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&ad_101).unwrap()))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "101st advertisement must be rejected with 429"
        );
    }

    #[tokio::test]
    async fn rate_limit_allows_different_principals() {
        let state = make_rate_limit_state(1).await;
        let app = router().with_state(state);

        let kp1 = PrincipalKeypair::generate();
        let kp2 = PrincipalKeypair::generate();

        // First principal: 1 ad — accepted (at limit)
        let ad1 = make_ad(&kp1, "Agent KP1");
        let req1 = Request::builder()
            .method("POST")
            .uri("/api/agents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&ad1).unwrap()))
            .unwrap();
        let resp1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::CREATED);

        // Second principal: 1 ad — must also be accepted (independent counter)
        let ad2 = make_ad(&kp2, "Agent KP2");
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/agents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&ad2).unwrap()))
            .unwrap();
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::CREATED);

        // First principal: 2nd ad — must be rejected
        let ad1b = make_ad(&kp1, "Agent KP1-B");
        let req1b = Request::builder()
            .method("POST")
            .uri("/api/agents")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&ad1b).unwrap()))
            .unwrap();
        let resp1b = app.clone().oneshot(req1b).await.unwrap();
        assert_eq!(resp1b.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
```

### Step 10.6 — Run and commit

- [ ] `cargo test -p pap-registry -- rate_limit` — expected: both tests pass
- [ ] Commit: `feat(registry): enforce per-principal advertisement rate limit (max 100)`

---

## Acceptance criteria

- [ ] `cargo test -p papillon -- state::` — all pass
- [ ] `cargo build -p papillon` — compiles without errors or warnings
- [ ] `cargo test -p pap-registry -- rate_limit` — all pass
- [ ] `cargo clippy -p papillon -p pap-registry -- -D warnings` — clean
- [ ] No `unwrap()` in command bodies in `commands/agents.rs` — all errors mapped with `.map_err(|e| e.to_string())`
- [ ] `HttpEndpointConfig` (including `headers`) does not appear in any `AgentInfo` returned by any Tauri command
- [ ] `operator_key_seed` does not appear in any `AgentInfo` or any Tauri IPC response

---

## Implementation notes

**AppState lock discipline** (from existing codebase patterns):
- `state.local_registry.lock().unwrap()` → replace with `.map_err(|e| format!("Registry lock poisoned: {e}"))` in command bodies
- `state.agent_keypairs.write().unwrap()` → replace with `.map_err(|e| format!("Keypair lock poisoned: {e}"))` in command bodies
- `state.orchestrator_config.read().unwrap()` → replace with `.map_err(|e| format!("Config lock poisoned: {e}"))` in command bodies

**`DynamicAgentDef` import path:** `use pap_agents::DynamicAgentDef;`

**`pap_marketplace::AgentAdvertisement` access:** already transitive via `pap-agents` dependency.

**Catalog directory in tests:** the `make_app_state()` test helper in `state.rs` uses
`PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog")`. If no catalog directory exists
at that path, `load_catalog` should return an empty `Vec` (not panic) — verify this behavior
is implemented in Part 2.

**`AgentAdvertisement::signed_by` field:** the field name used in the rate limit SQL query
must exactly match what the migration creates. Check `src/db/migrations/sqlite/` to confirm
whether the column is `signed_by`, `provider_did`, or another name, and adjust the query
in Steps 10.3 and 10.4 accordingly.
