//! WebService: Direct IndexedDB backend for WASM environments.
//!
//! This implementation provides a fallback for running Papillon in a pure
//! WebAssembly environment without Tauri. It delegates to WebIdentityService
//! for identity/profile management (Ed25519 keypairs in IndexedDB) and wires
//! agent/registry operations to `WasmAgentRegistry` backed by IndexedDB.
//!
//! # Design
//!
//! - **Identity & profiles**: Backed by `WebIdentityService` using `pap-did`
//!   for Ed25519 keypair generation and IndexedDB for seed persistence
//! - **Registry**: Backed by `WasmAgentRegistry` (IndexedDB) with the default
//!   catalog seeded on first open
//! - **Stub implementations**: Operations requiring backend logic (orchestrator,
//!   scenario execution) return errors or sensible defaults
//! - **No IPC overhead**: Direct database access provides lower latency

use std::sync::Mutex;

use pap_did::PrincipalKeypair;
#[cfg(feature = "wasm")]
use papillon_shared::WasmAgentRegistry;

use super::web_identity::WebIdentityService;
use super::{AgentProfileInfo, PapillonService};
use papillon_shared::{
    AgentInfo, IdentityInfo, OrchestratorConfig, OrchestratorStatus, ProfileMetadata, RegistryInfo,
    ScenarioCard, ScenarioRunResult, SetupState, Template,
};
use serde_json::Value;

/// The built-in local registry URL recognised as "this device's registry".
#[cfg(feature = "wasm")]
const LOCAL_REGISTRY_URL: &str = "pap://local";

/// Service implementation for pure WASM environments with IndexedDB.
///
/// Holds a `WebIdentityService` for identity/profile management and a
/// `WasmAgentRegistry` for local agent storage. Uses `std::sync::Mutex`
/// (not `RefCell`) to satisfy `Send + Sync` bounds required by
/// `PapillonService`. This is safe because WASM is single-threaded —
/// the mutex never actually contends.
pub struct WebService {
    identity: Mutex<WebIdentityService>,
    #[cfg(feature = "wasm")]
    registry: Mutex<WasmAgentRegistry>,
}

impl WebService {
    /// Initialize the web service by loading profiles from IndexedDB and
    /// seeding the default agent catalog.
    pub async fn new() -> Result<Self, String> {
        let identity = WebIdentityService::load().await?;

        #[cfg(feature = "wasm")]
        let registry = {
            // On real wasm32 targets, open() awaits the IndexedDB promise.
            // On native (--features wasm tests), new_empty() provides a
            // synchronous in-memory alternative that is used instead.
            #[cfg(target_arch = "wasm32")]
            let mut reg = WasmAgentRegistry::open("papillon-agents")
                .await
                .map_err(|e| format!("Failed to open agent registry: {e}"))?;

            #[cfg(not(target_arch = "wasm32"))]
            let mut reg = WasmAgentRegistry::new_empty("papillon-agents")
                .map_err(|e| format!("Failed to create agent registry: {e}"))?;

            // seed_default_catalog is async on wasm32, sync on native.
            // Seeding failure is a soft-error — the registry remains usable
            // (empty) and the user can still interact with the app.
            #[cfg(target_arch = "wasm32")]
            if let Err(e) = reg.seed_default_catalog().await {
                web_sys::console::warn_1(
                    &format!(
                        "WebService: catalog seeding failed (continuing with empty registry): {e}"
                    )
                    .into(),
                );
            }

            #[cfg(not(target_arch = "wasm32"))]
            if let Err(_e) = reg.seed_default_catalog() {
                // Suppress unused-variable warning in tests; the failure is non-fatal.
                let _ = ();
            }

            reg
        };

        Ok(Self {
            identity: Mutex::new(identity),
            #[cfg(feature = "wasm")]
            registry: Mutex::new(registry),
        })
    }

    /// Create a service with no loaded profiles (fallback for init failures).
    pub fn empty() -> Self {
        Self {
            identity: Mutex::new(WebIdentityService::empty()),
            #[cfg(feature = "wasm")]
            registry: Mutex::new(
                // new_empty can only fail if the in-memory DB itself can't be
                // created — essentially unreachable on any supported platform.
                WasmAgentRegistry::new_empty("papillon-agents-empty")
                    .expect("in-memory registry must succeed"),
            ),
        }
    }
}

/// Convert an `AgentAdvertisement` into the frontend-facing `AgentInfo` DTO.
///
/// Mirrors the `ad_to_info` helper in `apps/papillon/src/commands/registry.rs`
/// for the Tauri path, keeping the two representations in sync.
#[cfg(feature = "wasm")]
fn ad_to_info(ad: &pap_marketplace::AgentAdvertisement) -> AgentInfo {
    AgentInfo {
        name: ad.name.clone(),
        provider_name: ad.provider.name.clone(),
        provider_did: ad.provider.did.clone(),
        capabilities: ad.capability.clone(),
        object_types: ad.object_types.clone(),
        requires_disclosure: ad.requires_disclosure.clone(),
        returns: ad.returns.clone(),
        content_hash: ad.hash(),
        endpoint: None,
        agent_did: None,
        // "catalog" is the correct value for agents seeded from the embedded catalog.
        // Note: the Tauri registry.rs ad_to_info currently uses "" — that's a known gap
        // in the native implementation, not the correct behavior.
        source: "catalog".to_owned(),
        published_to: vec![],
        // Catalog agents are seeded locally and are directly invocable.
        live: true,
        category: "general".to_owned(),
    }
}

#[async_trait::async_trait(?Send)]
impl PapillonService for WebService {
    // ============================================================================
    // TEMPLATES
    // ============================================================================

    async fn get_global_templates(&self) -> Result<Vec<Template>, String> {
        // TODO: Implement IndexedDB read for global templates
        Err("WebService: get_global_templates not yet implemented".into())
    }

    async fn get_profile_templates(&self, _principal_did: &str) -> Result<Vec<Template>, String> {
        // TODO: Implement IndexedDB read for profile-specific templates
        Err("WebService: get_profile_templates not yet implemented".into())
    }

    async fn create_template(&self, _template: &Template) -> Result<(), String> {
        // TODO: Implement IndexedDB write for new template
        Err("WebService: create_template not yet implemented".into())
    }

    async fn update_template(&self, _template: &Template) -> Result<(), String> {
        // TODO: Implement IndexedDB update for template
        Err("WebService: update_template not yet implemented".into())
    }

    async fn delete_template(&self, _template_name: &str) -> Result<(), String> {
        // TODO: Implement IndexedDB delete for template
        Err("WebService: delete_template not yet implemented".into())
    }

    async fn set_template_enabled(
        &self,
        _template_name: &str,
        _enabled: bool,
    ) -> Result<(), String> {
        // TODO: Implement IndexedDB update for template enabled flag
        Err("WebService: set_template_enabled not yet implemented".into())
    }

    // ============================================================================
    // PROFILES — delegated to WebIdentityService
    // ============================================================================

    async fn list_profiles(&self) -> Result<Vec<ProfileMetadata>, String> {
        let identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        Ok(identity.list_profiles())
    }

    // WASM is single-threaded; holding a std::sync::MutexGuard across an
    // await point cannot cause a deadlock here.
    #[allow(clippy::await_holding_lock)]
    async fn create_profile(&self, name: &str) -> Result<ProfileMetadata, String> {
        let mut identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        identity.create_profile(name).await
    }

    // WASM is single-threaded; holding a std::sync::MutexGuard across an
    // await point cannot cause a deadlock here.
    #[allow(clippy::await_holding_lock)]
    async fn switch_profile(&self, profile_id: &str) -> Result<IdentityInfo, String> {
        let mut identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        identity.switch_profile(profile_id).await
    }

    // ============================================================================
    // IDENTITY — delegated to WebIdentityService
    // ============================================================================

    async fn get_identity(&self) -> Result<IdentityInfo, String> {
        let identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        identity
            .get_identity()
            .ok_or_else(|| "No active identity".to_string())
    }

    fn active_keypair(&self) -> Result<PrincipalKeypair, String> {
        let identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        identity.active_keypair()
    }

    // ============================================================================
    // REGISTRY & AGENTS
    // ============================================================================

    async fn navigate_registry(&self, url: &str) -> Result<RegistryInfo, String> {
        #[cfg(feature = "wasm")]
        {
            // WASM supports only the local registry; remote federation is not yet implemented.
            // Return an error for any non-local URL rather than silently serving local data.
            const LOCAL_URLS: &[&str] = &["", "pap://local", "local"];
            if !LOCAL_URLS.iter().any(|&u| u == url.trim()) {
                return Err(format!(
                    "WebService: remote registry navigation not supported in WASM \
                     (url: '{url}'); only the local agent catalog is available"
                ));
            }
            let registry = self
                .registry
                .lock()
                .map_err(|e| format!("registry lock: {e}"))?;
            return Ok(RegistryInfo {
                url: LOCAL_REGISTRY_URL.to_owned(),
                agent_count: registry.agent_count(),
                // WASM runs locally — no federation peers.
                peer_count: 0,
            });
        }
        #[cfg(not(feature = "wasm"))]
        Err("WebService: navigate_registry not available without wasm feature".into())
    }

    async fn list_registry_agents(&self, registry_url: &str) -> Result<Vec<AgentInfo>, String> {
        #[cfg(feature = "wasm")]
        {
            let registry = self
                .registry
                .lock()
                .map_err(|e| format!("registry lock: {e}"))?;
            // NOTE: `registry_url` is overloaded here: if it starts with "schema:", it is treated
            // as a Schema.org action type for capability filtering; otherwise it is treated as a
            // registry URL (only "pap://local" or empty is supported in WASM).
            let ads = if registry_url.starts_with("schema:") {
                registry.query_by_action(registry_url)
            } else {
                registry.list_agents()
            };
            return Ok(ads.iter().map(ad_to_info).collect());
        }
        #[cfg(not(feature = "wasm"))]
        {
            let _ = registry_url;
            Err("WebService: list_registry_agents requires wasm feature".into())
        }
    }

    // ============================================================================
    // ORCHESTRATOR
    // ============================================================================

    async fn get_orchestrator_config(&self) -> Result<OrchestratorConfig, String> {
        // TODO: Implement IndexedDB read for orchestrator config
        Err("WebService: get_orchestrator_config not yet implemented".into())
    }

    async fn configure_orchestrator(
        &self,
        _config: &OrchestratorConfig,
    ) -> Result<OrchestratorConfig, String> {
        // TODO: Implement IndexedDB write for orchestrator config
        Err("WebService: configure_orchestrator not yet implemented".into())
    }

    async fn get_orchestrator_status(&self) -> Result<OrchestratorStatus, String> {
        // Orchestrator status requires runtime state from backend.
        Err("WebService: get_orchestrator_status not yet implemented (requires backend)".into())
    }

    // ============================================================================
    // SETUP & STATE
    // ============================================================================

    async fn get_setup_state(&self) -> Result<SetupState, String> {
        // TODO: Implement IndexedDB read for setup state
        Err("WebService: get_setup_state not yet implemented".into())
    }

    // WASM is single-threaded; holding a std::sync::MutexGuard across an
    // await point cannot cause a deadlock here.
    #[allow(clippy::await_holding_lock)]
    async fn initialize(&self) -> Result<(), String> {
        let loaded = super::web_identity::WebIdentityService::load().await?;
        let mut identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        *identity = loaded;

        // Auto-create a default profile if none exist
        if identity.list_profiles().is_empty() {
            identity.create_profile("Default").await?;
            // Activate the newly created profile
            let profiles = identity.list_profiles();
            if let Some(first) = profiles.first() {
                identity.switch_profile(&first.id).await?;
            }
        }

        // The registry catalog was seeded in new(). initialize() is called
        // post-construction, so no additional seeding is required here.

        Ok(())
    }

    // ============================================================================
    // SCENARIOS & EPISODES
    // ============================================================================

    async fn list_scenarios(&self) -> Result<Vec<ScenarioCard>, String> {
        // TODO: Implement IndexedDB read for scenarios
        Err("WebService: list_scenarios not yet implemented".into())
    }

    async fn list_completed_runs(&self) -> Result<Vec<ScenarioRunResult>, String> {
        // TODO: Implement IndexedDB read for run results
        Err("WebService: list_completed_runs not yet implemented".into())
    }

    async fn run_scenario(
        &self,
        _scenario_id: &str,
        _params: &Value,
    ) -> Result<ScenarioRunResult, String> {
        // Scenario execution requires backend orchestrator.
        Err("WebService: run_scenario not yet implemented (requires backend)".into())
    }

    // ============================================================================
    // AGENT PROFILES
    // ============================================================================

    async fn list_agent_profiles(&self) -> Result<Vec<AgentProfileInfo>, String> {
        // TODO: Implement IndexedDB read for agent profiles
        Err("WebService: list_agent_profiles not yet implemented".into())
    }

    async fn create_agent_profile(
        &self,
        _name: &str,
        _agent_did: &str,
    ) -> Result<AgentProfileInfo, String> {
        // TODO: Implement IndexedDB write for new agent profile
        Err("WebService: create_agent_profile not yet implemented".into())
    }

    async fn update_agent_profile(&self, _profile: &AgentProfileInfo) -> Result<(), String> {
        // TODO: Implement IndexedDB update for agent profile
        Err("WebService: update_agent_profile not yet implemented".into())
    }

    async fn delete_agent_profile(&self, _profile_id: &str) -> Result<(), String> {
        // TODO: Implement IndexedDB delete for agent profile
        Err("WebService: delete_agent_profile not yet implemented".into())
    }
}
