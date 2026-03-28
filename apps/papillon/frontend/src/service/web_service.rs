//! WebService: Direct IndexedDB backend for WASM environments.
//!
//! This implementation provides a fallback for running Papillon in a pure
//! WebAssembly environment without Tauri. It delegates to WebIdentityService
//! for identity/profile management (Ed25519 keypairs in IndexedDB) and returns
//! stub errors for operations that require backend compute.
//!
//! # Design
//!
//! - **Identity & profiles**: Backed by `WebIdentityService` using `pap-did`
//!   for Ed25519 keypair generation and IndexedDB for seed persistence
//! - **Stub implementations**: Operations requiring backend logic (orchestrator,
//!   registry discovery, scenario execution) return errors or sensible defaults
//! - **No IPC overhead**: Direct database access provides lower latency

use std::sync::Mutex;

use pap_did::PrincipalKeypair;

use super::web_identity::WebIdentityService;
use super::{AgentProfileInfo, PapillonService};
use papillon_shared::{
    AgentInfo, IdentityInfo, OrchestratorConfig, OrchestratorStatus, ProfileMetadata, RegistryInfo,
    ScenarioCard, ScenarioRunResult, SetupState, Template,
};
use serde_json::Value;

/// Service implementation for pure WASM environments with IndexedDB.
///
/// Holds a `WebIdentityService` for identity/profile management. Uses
/// `std::sync::Mutex` (not `RefCell`) to satisfy `Send + Sync` bounds
/// required by `PapillonService`. This is safe because WASM is
/// single-threaded — the mutex never actually contends.
pub struct WebService {
    identity: Mutex<WebIdentityService>,
}

impl WebService {
    /// Initialize the web service by loading profiles from IndexedDB.
    pub async fn new() -> Result<Self, String> {
        let identity = WebIdentityService::load().await?;
        Ok(Self {
            identity: Mutex::new(identity),
        })
    }

    /// Create a service with no loaded profiles (fallback for init failures).
    pub fn empty() -> Self {
        Self {
            identity: Mutex::new(WebIdentityService::empty()),
        }
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

    async fn create_profile(&self, name: &str) -> Result<ProfileMetadata, String> {
        let mut identity = self
            .identity
            .lock()
            .map_err(|e| format!("identity lock: {e}"))?;
        identity.create_profile(name).await
    }

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

    async fn navigate_registry(&self, _url: &str) -> Result<RegistryInfo, String> {
        // Registry discovery requires network access and TOFU bootstrap.
        Err("WebService: navigate_registry not yet implemented (requires network)".into())
    }

    async fn list_registry_agents(&self, _registry_url: &str) -> Result<Vec<AgentInfo>, String> {
        // Requires network access to fetch agents from registry.
        Err("WebService: list_registry_agents not yet implemented (requires network)".into())
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
