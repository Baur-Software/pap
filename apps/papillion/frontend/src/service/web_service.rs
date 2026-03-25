//! WebService: Direct IndexedDB backend for WASM environments.
//!
//! This implementation provides a fallback for running Papillion in a pure
//! WebAssembly environment without Tauri. It delegates to IndexedDbDatabase
//! for persistence and implements stub methods for operations that require
//! backend compute (like orchestrator).
//!
//! # Design
//!
//! - **Local storage**: Templates, profiles, and agent metadata use IndexedDB
//! - **Stub implementations**: Operations requiring backend logic (orchestrator,
//!   registry discovery, scenario execution) return errors or sensible defaults
//! - **No IPC overhead**: Direct database access provides lower latency

use super::{AgentProfileInfo, PapillionService};
use papillion_shared::{
    AgentInfo, IdentityInfo, OrchestratorConfig, OrchestratorStatus, ProfileMetadata, RegistryInfo,
    ScenarioCard, ScenarioRunResult, SetupState, Template,
};
use serde_json::Value;

/// Service implementation for pure WASM environments with IndexedDB.
///
/// This is a placeholder implementation that demonstrates the abstraction.
/// In production, it would be backed by an actual IndexedDB interface
/// accessible from WASM (e.g., `web_sys`, `wasm_bindgen`, or a dedicated IndexedDB crate).
pub struct WebService;

#[async_trait::async_trait(?Send)]
impl PapillionService for WebService {
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
    // PROFILES
    // ============================================================================

    async fn list_profiles(&self) -> Result<Vec<ProfileMetadata>, String> {
        // TODO: Implement IndexedDB read for profiles
        Err("WebService: list_profiles not yet implemented".into())
    }

    async fn create_profile(&self, _name: &str) -> Result<ProfileMetadata, String> {
        // TODO: Implement IndexedDB write for new profile
        Err("WebService: create_profile not yet implemented".into())
    }

    async fn switch_profile(&self, _profile_id: &str) -> Result<IdentityInfo, String> {
        // TODO: Implement profile switching and identity derivation
        Err("WebService: switch_profile not yet implemented".into())
    }

    // ============================================================================
    // IDENTITY
    // ============================================================================

    async fn get_identity(&self) -> Result<IdentityInfo, String> {
        // TODO: Implement identity state retrieval
        Err("WebService: get_identity not yet implemented".into())
    }

    // ============================================================================
    // REGISTRY & AGENTS
    // ============================================================================

    async fn navigate_registry(&self, _url: &str) -> Result<RegistryInfo, String> {
        // Registry discovery requires network access and TOFU bootstrap.
        // Stub implementation for web environment.
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
        // Stub implementation for web environment.
        Err("WebService: get_orchestrator_status not yet implemented (requires backend)".into())
    }

    // ============================================================================
    // SETUP & STATE
    // ============================================================================

    async fn get_setup_state(&self) -> Result<SetupState, String> {
        // TODO: Implement IndexedDB read for setup state
        Err("WebService: get_setup_state not yet implemented".into())
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
