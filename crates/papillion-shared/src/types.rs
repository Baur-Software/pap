use serde::{Deserialize, Serialize};

/// Principal identity information (never contains private keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub did: String,
    pub public_key_b64: String,
    pub created_at: String,
}

/// Summary of a connected registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInfo {
    pub url: String,
    pub agent_count: usize,
    pub peer_count: usize,
}

/// Agent information for display in the registry browser.
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
}

/// Federation peer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub endpoint: String,
    pub did: String,
    pub last_sync: Option<String>,
}

/// Active session information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_name: String,
    pub agent_did: String,
    pub action: String,
    pub state: String,
    pub handshake_phase: u8,
    pub created_at: String,
}

/// Mandate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateInfo {
    pub issuer_did: String,
    pub subject_did: String,
    pub actions: Vec<String>,
    pub ttl_hours: u64,
    pub decay_state: String,
}

/// Pipeline definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineInfo {
    pub id: String,
    pub name: String,
    pub nodes: Vec<PipelineNodeInfo>,
    pub edges: Vec<PipelineEdgeInfo>,
    pub created_at: String,
}

/// A node in a pipeline (represents an agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineNodeInfo {
    pub id: String,
    pub agent_hash: String,
    pub agent_name: String,
    pub position_x: f64,
    pub position_y: f64,
}

/// An edge in a pipeline (data flow between agents).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEdgeInfo {
    pub from_node: String,
    pub to_node: String,
}

/// Pipeline execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineExecutionResult {
    pub pipeline_id: String,
    pub steps_completed: usize,
    pub steps_total: usize,
    pub results: Vec<PipelineStepResult>,
}

/// Result of a single pipeline step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStepResult {
    pub node_id: String,
    pub session_id: String,
    pub success: bool,
    pub result_json: Option<String>,
    pub error: Option<String>,
}

/// Transaction receipt information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptInfo {
    pub session_id: String,
    pub action: String,
    pub initiator_did: String,
    pub receiver_did: String,
    pub property_refs: Vec<String>,
    pub co_signed: bool,
    pub timestamp: String,
}

/// Receipt verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptVerificationResult {
    pub session_id: String,
    pub initiator_signature_valid: bool,
    pub receiver_signature_valid: bool,
}

/// Application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub default_ttl_hours: u64,
    pub theme: String,
    pub bookmarks: Vec<String>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            default_ttl_hours: 24,
            theme: "dark".into(),
            bookmarks: Vec::new(),
        }
    }
}

// ── Orchestrator types ──────────────────────────────────────

/// LLM provider for the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum LlmProvider {
    BuiltIn,
    Ollama { endpoint: String, model: String },
    OpenAiCompatible { endpoint: String, api_key: String, model: String },
    #[default]
    None,
}

/// Orchestrator configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestratorConfig {
    pub llm_provider: LlmProvider,
    pub mandate_ttl_hours: u64,
    pub auto_approve_zero_disclosure: bool,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            llm_provider: LlmProvider::None,
            mandate_ttl_hours: 8,
            auto_approve_zero_disclosure: true,
        }
    }
}

/// Orchestrator runtime status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OrchestratorStatus {
    Unconfigured,
    Disconnected,
    Ready,
    DemoOnly,
}

/// First-run setup state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupState {
    pub identity_created: bool,
    pub llm_configured: bool,
    pub setup_complete: bool,
}

/// A user-facing scenario card for the Home page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioCard {
    pub id: String,
    pub title: String,
    pub description: String,
    pub icon: String,
    pub agent_name: String,
    pub action_type: String,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
}
