//! TauriService: Delegates all operations to Tauri IPC bridge.
//!
//! This implementation bridges frontend calls to backend Tauri commands.
//! Each method translates the request into a Tauri invoke call and
//! deserializes the response.

use pap_did::PrincipalKeypair;

use super::{AgentProfileInfo, PapillonService};
use crate::bridge;
use papillon_shared::{
    AgentInfo, IdentityInfo, OrchestratorConfig, OrchestratorStatus, ProfileMetadata, RegistryInfo,
    ScenarioCard, ScenarioRunResult, SetupState, Template,
};
use serde_json::{json, Value};

/// Service implementation that delegates to Tauri IPC bridge.
pub struct TauriService;

#[async_trait::async_trait(?Send)]
impl PapillonService for TauriService {
    // ============================================================================
    // TEMPLATES
    // ============================================================================

    async fn get_global_templates(&self) -> Result<Vec<Template>, String> {
        bridge::invoke_no_args::<Vec<Template>>("get_global_templates").await
    }

    async fn get_profile_templates(&self, principal_did: &str) -> Result<Vec<Template>, String> {
        bridge::invoke::<Value, Vec<Template>>(
            "get_profile_templates",
            &json!({ "principal_did": principal_did }),
        )
        .await
    }

    async fn create_template(&self, template: &Template) -> Result<(), String> {
        bridge::invoke::<Value, ()>("create_template", &json!({ "template": template })).await
    }

    async fn update_template(&self, template: &Template) -> Result<(), String> {
        bridge::invoke::<Value, ()>("update_template", &json!({ "template": template })).await
    }

    async fn delete_template(&self, template_name: &str) -> Result<(), String> {
        bridge::invoke::<Value, ()>(
            "delete_template",
            &json!({ "template_name": template_name }),
        )
        .await
    }

    async fn set_template_enabled(&self, template_name: &str, enabled: bool) -> Result<(), String> {
        bridge::invoke::<Value, ()>(
            "set_template_enabled",
            &json!({ "template_name": template_name, "enabled": enabled }),
        )
        .await
    }

    // ============================================================================
    // PROFILES
    // ============================================================================

    async fn list_profiles(&self) -> Result<Vec<ProfileMetadata>, String> {
        bridge::invoke_no_args::<Vec<ProfileMetadata>>("list_profiles").await
    }

    async fn create_profile(&self, name: &str) -> Result<ProfileMetadata, String> {
        bridge::invoke::<Value, ProfileMetadata>("create_profile", &json!({ "name": name })).await
    }

    async fn switch_profile(&self, profile_id: &str) -> Result<IdentityInfo, String> {
        bridge::invoke::<Value, IdentityInfo>(
            "switch_profile",
            &json!({ "profile_id": profile_id }),
        )
        .await
    }

    // ============================================================================
    // IDENTITY
    // ============================================================================

    async fn get_identity(&self) -> Result<IdentityInfo, String> {
        bridge::invoke_no_args::<IdentityInfo>("get_identity").await
    }

    fn active_keypair(&self) -> Result<PrincipalKeypair, String> {
        Err("active_keypair not available in Tauri mode (keypair lives on native backend)".into())
    }

    // ============================================================================
    // REGISTRY & AGENTS
    // ============================================================================

    async fn navigate_registry(&self, url: &str) -> Result<RegistryInfo, String> {
        bridge::invoke::<Value, RegistryInfo>("navigate_registry", &json!({ "url": url })).await
    }

    async fn list_registry_agents(&self, registry_url: &str) -> Result<Vec<AgentInfo>, String> {
        bridge::invoke::<Value, Vec<AgentInfo>>(
            "list_agents",
            &json!({ "registry_url": registry_url }),
        )
        .await
    }

    // ============================================================================
    // ORCHESTRATOR
    // ============================================================================

    async fn get_orchestrator_config(&self) -> Result<OrchestratorConfig, String> {
        bridge::invoke_no_args::<OrchestratorConfig>("get_orchestrator_config").await
    }

    async fn configure_orchestrator(
        &self,
        config: &OrchestratorConfig,
    ) -> Result<OrchestratorConfig, String> {
        bridge::invoke::<Value, OrchestratorConfig>(
            "configure_orchestrator",
            &json!({ "config": config }),
        )
        .await
    }

    async fn get_orchestrator_status(&self) -> Result<OrchestratorStatus, String> {
        bridge::invoke_no_args::<OrchestratorStatus>("get_orchestrator_status").await
    }

    // ============================================================================
    // SETUP & STATE
    // ============================================================================

    async fn get_setup_state(&self) -> Result<SetupState, String> {
        bridge::invoke_no_args::<SetupState>("get_setup_state").await
    }

    // ============================================================================
    // SCENARIOS & EPISODES
    // ============================================================================

    async fn list_scenarios(&self) -> Result<Vec<ScenarioCard>, String> {
        bridge::invoke_no_args::<Vec<ScenarioCard>>("list_scenarios").await
    }

    async fn list_completed_runs(&self) -> Result<Vec<ScenarioRunResult>, String> {
        bridge::invoke_no_args::<Vec<ScenarioRunResult>>("list_completed_runs").await
    }

    async fn run_scenario(
        &self,
        scenario_id: &str,
        params: &Value,
    ) -> Result<ScenarioRunResult, String> {
        bridge::invoke::<Value, ScenarioRunResult>(
            "run_scenario",
            &json!({ "scenario_id": scenario_id, "params": params }),
        )
        .await
    }

    // ============================================================================
    // AGENT PROFILES
    // ============================================================================

    async fn list_agent_profiles(&self) -> Result<Vec<AgentProfileInfo>, String> {
        bridge::invoke_no_args::<Vec<AgentProfileInfo>>("list_agent_profiles").await
    }

    async fn create_agent_profile(
        &self,
        name: &str,
        agent_did: &str,
    ) -> Result<AgentProfileInfo, String> {
        bridge::invoke::<Value, AgentProfileInfo>(
            "create_agent_profile",
            &json!({ "name": name, "agent_did": agent_did }),
        )
        .await
    }

    async fn update_agent_profile(&self, profile: &AgentProfileInfo) -> Result<(), String> {
        bridge::invoke::<Value, ()>("update_agent_profile", &json!({ "profile": profile })).await
    }

    async fn delete_agent_profile(&self, profile_id: &str) -> Result<(), String> {
        bridge::invoke::<Value, ()>("delete_agent_profile", &json!({ "profile_id": profile_id }))
            .await
    }
}
