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

/// Known built-in models that ship with Papillion.
/// Each entry maps to a HuggingFace repo + GGUF filename.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuiltInModelInfo {
    pub id: String,
    pub display_name: String,
    pub repo: String,
    pub filename: String,
    pub size_hint: String,
}

/// Catalog of known models. The first entry is the default.
pub fn builtin_model_catalog() -> Vec<BuiltInModelInfo> {
    vec![
        BuiltInModelInfo {
            id: "mistral-7b-instruct".into(),
            display_name: "Mistral 7B Instruct (Q4)".into(),
            repo: "TheBloke/Mistral-7B-Instruct-v0.2-GGUF".into(),
            filename: "mistral-7b-instruct-v0.2.Q4_K_M.gguf".into(),
            size_hint: "~4.4 GB".into(),
        },
        BuiltInModelInfo {
            id: "phi-3-mini".into(),
            display_name: "Phi-3 Mini (Q4)".into(),
            repo: "microsoft/Phi-3-mini-4k-instruct-gguf".into(),
            filename: "Phi-3-mini-4k-instruct-q4.gguf".into(),
            size_hint: "~2.3 GB".into(),
        },
        BuiltInModelInfo {
            id: "tinyllama-1.1b".into(),
            display_name: "TinyLlama 1.1B (Q4)".into(),
            repo: "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF".into(),
            filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
            size_hint: "~0.6 GB".into(),
        },
    ]
}

/// LLM provider for the orchestrator.
///
/// The default is `BuiltIn` with Mistral — inference runs locally via Candle
/// with no HTTP calls, which is the intended PAP architecture. The Ollama and
/// OpenAI-compatible options are provided for advanced users but require
/// network access that weakens PAP's zero-trust guarantees.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LlmProvider {
    /// On-device inference via Candle. Model is downloaded once from
    /// HuggingFace Hub, then runs entirely offline.
    #[serde(alias = "BuiltIn")]
    BuiltIn { model_id: String },
    /// External Ollama instance (requires HTTP). Use only if you already
    /// run Ollama and understand the privacy trade-off.
    Ollama { endpoint: String, model: String },
    /// Any OpenAI-compatible HTTP API (requires network + API key).
    OpenAiCompatible { endpoint: String, api_key: String, model: String },
    /// Demo mode — no LLM, hardcoded scenarios only.
    None,
}

impl Default for LlmProvider {
    fn default() -> Self {
        LlmProvider::BuiltIn {
            model_id: "mistral-7b-instruct".into(),
        }
    }
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
            llm_provider: LlmProvider::default(),
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
    /// Model is being downloaded from HuggingFace Hub.
    Downloading { progress_pct: u8 },
    /// Model loaded, ready for inference.
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
    /// Agent DID for real protocol execution.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub agent_did: Option<String>,
    /// HTTP endpoint for real protocol execution. None = demo agent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint: Option<String>,
}

// ── Demo runner types ─────────────────────────────────────

/// Result of running a demo scenario through the full 6-step handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoRunResult {
    pub scenario_id: String,
    pub agent_name: String,
    pub steps: Vec<DemoStepResult>,
    pub receipt: Option<ReceiptInfo>,
    pub receipt_url: Option<String>,
    pub query: Option<String>,
    pub search_results: Option<Vec<SearchResult>>,
    pub completed_at: String,
    pub success: bool,
    pub error: Option<String>,
}

/// A web search result returned by the search agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// Result of a single handshake step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoStepResult {
    pub step_number: u8,
    pub step_name: String,
    pub status: String,
    pub detail: Option<String>,
    pub timestamp: String,
}

// ── Identity management types ─────────────────────────────

/// Exported key material (base64url-encoded 32-byte seed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedKey {
    pub seed_b64: String,
    pub did: String,
    pub exported_at: String,
}

/// A forward-looking successor designation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessorDesignation {
    pub successor_did: String,
    pub relationship: String,
    pub notes: String,
    pub created_at: String,
}

/// Whether the key has been backed up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBackupStatus {
    pub backed_up: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Model catalog ────────────────────────────────────────

    #[test]
    fn catalog_is_non_empty() {
        let catalog = builtin_model_catalog();
        assert!(!catalog.is_empty());
    }

    #[test]
    fn catalog_default_is_mistral() {
        let catalog = builtin_model_catalog();
        assert_eq!(catalog[0].id, "mistral-7b-instruct");
    }

    #[test]
    fn catalog_ids_are_unique() {
        let catalog = builtin_model_catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|m| m.id.as_str()).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), catalog.len());
    }

    #[test]
    fn catalog_entries_have_required_fields() {
        for m in builtin_model_catalog() {
            assert!(!m.id.is_empty(), "id must be set");
            assert!(!m.display_name.is_empty(), "display_name must be set");
            assert!(!m.repo.is_empty(), "repo must be set");
            assert!(m.filename.ends_with(".gguf"), "filename must be .gguf");
            assert!(!m.size_hint.is_empty(), "size_hint must be set");
        }
    }

    // ── LlmProvider default & serde ─────────────────────────

    #[test]
    fn llm_provider_default_is_builtin_mistral() {
        let provider = LlmProvider::default();
        match &provider {
            LlmProvider::BuiltIn { model_id } => {
                assert_eq!(model_id, "mistral-7b-instruct");
            }
            other => panic!("Expected BuiltIn, got {other:?}"),
        }
    }

    #[test]
    fn llm_provider_none_not_equal_to_builtin() {
        assert_ne!(LlmProvider::None, LlmProvider::default());
    }

    #[test]
    fn llm_provider_builtin_roundtrip_json() {
        let provider = LlmProvider::BuiltIn {
            model_id: "phi-3-mini".into(),
        };
        let json = serde_json::to_string(&provider).unwrap();
        let back: LlmProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, back);
    }

    #[test]
    fn llm_provider_ollama_roundtrip_json() {
        let provider = LlmProvider::Ollama {
            endpoint: "http://localhost:11434".into(),
            model: "llama3.2:1b".into(),
        };
        let json = serde_json::to_string(&provider).unwrap();
        let back: LlmProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, back);
    }

    #[test]
    fn llm_provider_openai_roundtrip_json() {
        let provider = LlmProvider::OpenAiCompatible {
            endpoint: "https://api.example.com/v1".into(),
            api_key: "sk-test".into(),
            model: "gpt-4o".into(),
        };
        let json = serde_json::to_string(&provider).unwrap();
        let back: LlmProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, back);
    }

    #[test]
    fn llm_provider_none_roundtrip_json() {
        let provider = LlmProvider::None;
        let json = serde_json::to_string(&provider).unwrap();
        let back: LlmProvider = serde_json::from_str(&json).unwrap();
        assert_eq!(provider, back);
    }

    // ── OrchestratorConfig default ──────────────────────────

    #[test]
    fn orchestrator_config_default_uses_builtin() {
        let config = OrchestratorConfig::default();
        assert!(matches!(config.llm_provider, LlmProvider::BuiltIn { .. }));
        assert_eq!(config.mandate_ttl_hours, 8);
        assert!(config.auto_approve_zero_disclosure);
    }

    #[test]
    fn orchestrator_config_roundtrip_json() {
        let config = OrchestratorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: OrchestratorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.llm_provider, back.llm_provider);
        assert_eq!(config.mandate_ttl_hours, back.mandate_ttl_hours);
    }

    // ── OrchestratorStatus serde ────────────────────────────

    #[test]
    fn status_downloading_roundtrip_json() {
        let status = OrchestratorStatus::Downloading { progress_pct: 42 };
        let json = serde_json::to_string(&status).unwrap();
        let back: OrchestratorStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn status_ready_roundtrip_json() {
        let status = OrchestratorStatus::Ready;
        let json = serde_json::to_string(&status).unwrap();
        let back: OrchestratorStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    // ── BuiltInModelInfo serde ──────────────────────────────

    #[test]
    fn model_info_roundtrip_json() {
        let info = BuiltInModelInfo {
            id: "test-model".into(),
            display_name: "Test Model".into(),
            repo: "test/repo".into(),
            filename: "test.gguf".into(),
            size_hint: "~1 GB".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: BuiltInModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }
}
