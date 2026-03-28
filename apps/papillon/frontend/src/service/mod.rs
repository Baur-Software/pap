//! Service abstraction layer for Papillon frontend.
//!
//! This module provides a unified service interface that abstracts away the
//! difference between Tauri IPC and WebAssembly backends. The frontend dispatches
//! to the appropriate implementation based on runtime detection (`tauri_available()`).
//!
//! # Architecture
//!
//! - **PapillonService trait**: Defines all operations (template CRUD, settings,
//!   episodes, agent profiles, registry, orchestrator config)
//! - **TauriService**: Delegates to bridge::invoke (Tauri IPC)
//! - **WebService**: Delegates to IndexedDbDatabase directly (WASM/browser)
//!
//! # Usage
//!
//! ```ignore
//! // In App: provided as context during component creation
//! let service = use_papillon_service();
//! let templates = service.get_global_templates().await?;
//! ```

use serde::{Deserialize, Serialize};

use pap_did::PrincipalKeypair;
use papillon_shared::{
    AgentInfo, IdentityInfo, OrchestratorConfig, OrchestratorStatus, ProfileMetadata, RegistryInfo,
    ScenarioCard, ScenarioRunResult, SetupState, Template,
};

pub mod hooks;
pub mod tauri_service;
pub mod web_identity;
pub mod web_service;

pub use hooks::use_papillon_service;
pub use tauri_service::TauriService;
pub use web_service::WebService;

/// Trait defining all service operations for Papillon frontend.
///
/// This trait abstracts both Tauri and web-based backends, allowing the frontend
/// to dispatch to either implementation transparently.
#[async_trait::async_trait(?Send)]
pub trait PapillonService: Send + Sync {
    // ============================================================================
    // TEMPLATES: CRUD operations for user-defined templates
    // ============================================================================

    /// Fetch all enabled global templates.
    async fn get_global_templates(&self) -> Result<Vec<Template>, String>;

    /// Fetch enabled templates for a specific profile + global templates.
    async fn get_profile_templates(&self, principal_did: &str) -> Result<Vec<Template>, String>;

    /// Create a new template in the database.
    async fn create_template(&self, template: &Template) -> Result<(), String>;

    /// Update an existing template in the database.
    async fn update_template(&self, template: &Template) -> Result<(), String>;

    /// Delete a template from the database by name.
    async fn delete_template(&self, template_name: &str) -> Result<(), String>;

    /// Enable or disable a template without deleting it.
    async fn set_template_enabled(&self, template_name: &str, enabled: bool)
        -> Result<(), String>;

    // ============================================================================
    // PROFILES: List and manage principal profiles
    // ============================================================================

    /// List all profiles.
    async fn list_profiles(&self) -> Result<Vec<ProfileMetadata>, String>;

    /// Create a new profile with the given name.
    async fn create_profile(&self, name: &str) -> Result<ProfileMetadata, String>;

    /// Switch to a different profile.
    async fn switch_profile(&self, profile_id: &str) -> Result<IdentityInfo, String>;

    // ============================================================================
    // IDENTITY: Current identity and principal information
    // ============================================================================

    /// Get the current identity information.
    async fn get_identity(&self) -> Result<IdentityInfo, String>;

    /// Get the active principal keypair (with signing key).
    ///
    /// Only supported in WASM environments (WebService). Returns an error
    /// under Tauri where the keypair lives on the native backend.
    fn active_keypair(&self) -> Result<PrincipalKeypair, String>;

    // ============================================================================
    // REGISTRY & AGENTS: Browse and interact with agent registries
    // ============================================================================

    /// Navigate to a pap:// URL and discover agents.
    async fn navigate_registry(&self, url: &str) -> Result<RegistryInfo, String>;

    /// List agents at a specific registry.
    async fn list_registry_agents(&self, registry_url: &str) -> Result<Vec<AgentInfo>, String>;

    // ============================================================================
    // ORCHESTRATOR: Configuration and runtime state
    // ============================================================================

    /// Get the current orchestrator configuration.
    async fn get_orchestrator_config(&self) -> Result<OrchestratorConfig, String>;

    /// Save orchestrator configuration.
    async fn configure_orchestrator(&self, config: &OrchestratorConfig)
        -> Result<OrchestratorConfig, String>;

    /// Get the current orchestrator status.
    async fn get_orchestrator_status(&self) -> Result<OrchestratorStatus, String>;

    // ============================================================================
    // SETUP & STATE: Application initialization
    // ============================================================================

    /// Get the current setup state.
    async fn get_setup_state(&self) -> Result<SetupState, String>;

    /// Post-construction async initialization.
    ///
    /// Called after the service is provided as Leptos context. The WASM
    /// implementation uses this to load profiles from IndexedDB; the Tauri
    /// implementation is a no-op since backend state is ready at launch.
    async fn initialize(&self) -> Result<(), String> {
        Ok(())
    }

    // ============================================================================
    // SCENARIOS & EPISODES: Run and retrieve scenario results
    // ============================================================================

    /// List all available scenarios.
    async fn list_scenarios(&self) -> Result<Vec<ScenarioCard>, String>;

    /// List completed runs.
    async fn list_completed_runs(&self) -> Result<Vec<ScenarioRunResult>, String>;

    /// Run a scenario (with transaction receipt).
    async fn run_scenario(
        &self,
        scenario_id: &str,
        params: &serde_json::Value,
    ) -> Result<ScenarioRunResult, String>;

    // ============================================================================
    // AGENT PROFILES: Manage named agent configurations
    // ============================================================================

    /// List agent profiles for the current principal.
    async fn list_agent_profiles(&self) -> Result<Vec<AgentProfileInfo>, String>;

    /// Create a new agent profile.
    async fn create_agent_profile(
        &self,
        name: &str,
        agent_did: &str,
    ) -> Result<AgentProfileInfo, String>;

    /// Update an agent profile.
    async fn update_agent_profile(&self, profile: &AgentProfileInfo) -> Result<(), String>;

    /// Delete an agent profile.
    async fn delete_agent_profile(&self, profile_id: &str) -> Result<(), String>;
}

/// Shared data structure for agent profiles (consistent across service implementations).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentProfileInfo {
    pub id: String,
    pub name: String,
    pub agent_did: String,
    pub created_at: String,
    pub updated_at: String,
}

