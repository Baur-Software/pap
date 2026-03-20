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
    /// No LLM configured — keyword fallback only.
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
    Offline,
}

/// First-run setup state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupState {
    pub identity_created: bool,
    pub llm_configured: bool,
    pub setup_complete: bool,
}

// ── Canvas block types ────────────────────────────────────

/// The state of a canvas block during the PAP handshake lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BlockState {
    /// Handshake in progress — `phase` is 1..=6.
    Resolving { phase: u8, phase_label: String },
    /// Handshake completed, JSON-LD content available.
    Resolved,
    /// Handshake failed at a specific phase.
    Failed { phase: u8, reason: String },
}

/// A single block on the Papillion canvas.
///
/// Created by the backend when the orchestrator delegates a mandate.
/// Sent to the frontend via Tauri events (`block_created`, `block_updated`,
/// `block_resolved`, `block_failed`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasBlock {
    /// Unique block identifier.
    pub id: String,
    /// The prompt that spawned this block's mandate chain.
    pub prompt_id: String,
    /// Current lifecycle state.
    pub state: BlockState,
    /// Schema.org `@type` from the JSON-LD response (e.g. "FlightReservation").
    /// `None` while resolving.
    pub schema_type: Option<String>,
    /// Raw JSON-LD content returned by the agent. `None` while resolving.
    pub content: Option<serde_json::Value>,
    /// IDs of semantically linked blocks (same prompt, related data).
    pub linked_block_ids: Vec<String>,
    /// When this block was created.
    pub created_at: String,
    /// When this block was last updated.
    pub updated_at: String,
}

/// A saved canvas — a collection of blocks from prompt sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canvas {
    /// Unique canvas identifier.
    pub id: String,
    /// Auto-generated from the first prompt, or user-renamed.
    pub name: String,
    /// Ordered list of blocks on this canvas.
    pub blocks: Vec<CanvasBlock>,
    /// When this canvas was created.
    pub created_at: String,
    /// When this canvas was last modified.
    pub updated_at: String,
}

/// A prompt submitted via the command palette.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasPrompt {
    /// Unique prompt identifier — blocks reference this.
    pub id: String,
    /// The user's raw prompt text.
    pub text: String,
    /// If reshaping an existing block, its ID.
    pub reshape_block_id: Option<String>,
    /// Canvas this prompt belongs to.
    pub canvas_id: String,
    /// When this prompt was submitted.
    pub submitted_at: String,
}

/// Tauri event payloads for streaming block updates to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEvent {
    pub block: CanvasBlock,
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

// ── Handshake runner types ─────────────────────────────────

/// Result of running a scenario through the full 6-step PAP handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    pub scenario_id: String,
    pub agent_name: String,
    pub steps: Vec<StepResult>,
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
pub struct StepResult {
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

    // ── AppSettings default ───────────────────────────────

    #[test]
    fn app_settings_default_values() {
        let settings = AppSettings::default();
        assert_eq!(settings.default_ttl_hours, 24);
        assert_eq!(settings.theme, "dark");
        assert!(settings.bookmarks.is_empty());
    }

    #[test]
    fn app_settings_roundtrip_json() {
        let settings = AppSettings {
            default_ttl_hours: 48,
            theme: "light".into(),
            bookmarks: vec!["pap://registry.example".into()],
        };
        let json = serde_json::to_string(&settings).unwrap();
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.default_ttl_hours, 48);
        assert_eq!(back.theme, "light");
        assert_eq!(back.bookmarks.len(), 1);
    }

    // ── BlockState serde ──────────────────────────────────

    #[test]
    fn block_state_resolving_roundtrip_json() {
        let state = BlockState::Resolving {
            phase: 3,
            phase_label: "Opening session...".into(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: BlockState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn block_state_resolved_roundtrip_json() {
        let state = BlockState::Resolved;
        let json = serde_json::to_string(&state).unwrap();
        let back: BlockState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn block_state_failed_roundtrip_json() {
        let state = BlockState::Failed {
            phase: 4,
            reason: "Agent unreachable".into(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: BlockState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn block_state_variants_are_distinct() {
        let resolving = BlockState::Resolving {
            phase: 1,
            phase_label: "test".into(),
        };
        let resolved = BlockState::Resolved;
        let failed = BlockState::Failed {
            phase: 1,
            reason: "test".into(),
        };
        assert_ne!(resolving, resolved);
        assert_ne!(resolving, failed);
        assert_ne!(resolved, failed);
    }

    // ── CanvasBlock serde ─────────────────────────────────

    #[test]
    fn canvas_block_resolving_roundtrip_json() {
        let block = CanvasBlock {
            id: "blk-1".into(),
            prompt_id: "p-1".into(),
            state: BlockState::Resolving {
                phase: 2,
                phase_label: "Issuing mandate...".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: CanvasBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "blk-1");
        assert_eq!(back.prompt_id, "p-1");
        assert!(back.schema_type.is_none());
        assert!(back.content.is_none());
        assert!(back.linked_block_ids.is_empty());
    }

    #[test]
    fn canvas_block_resolved_with_content() {
        let content = serde_json::json!({
            "@type": "FlightReservation",
            "departureAirport": "SAN"
        });
        let block = CanvasBlock {
            id: "blk-2".into(),
            prompt_id: "p-1".into(),
            state: BlockState::Resolved,
            schema_type: Some("FlightReservation".into()),
            content: Some(content.clone()),
            linked_block_ids: vec!["blk-3".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:01Z".into(),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: CanvasBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_type.as_deref(), Some("FlightReservation"));
        assert_eq!(back.content.unwrap()["departureAirport"], "SAN");
        assert_eq!(back.linked_block_ids, vec!["blk-3"]);
    }

    #[test]
    fn canvas_block_failed_state() {
        let block = CanvasBlock {
            id: "blk-fail".into(),
            prompt_id: "p-1".into(),
            state: BlockState::Failed {
                phase: 5,
                reason: "Receipt co-sign rejected".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: CanvasBlock = serde_json::from_str(&json).unwrap();
        match back.state {
            BlockState::Failed { phase, reason } => {
                assert_eq!(phase, 5);
                assert_eq!(reason, "Receipt co-sign rejected");
            }
            other => panic!("Expected Failed, got {other:?}"),
        }
    }

    // ── Canvas serde ──────────────────────────────────────

    #[test]
    fn canvas_roundtrip_json() {
        let canvas = Canvas {
            id: "c-1".into(),
            name: "Flight to Tokyo".into(),
            blocks: vec![CanvasBlock {
                id: "blk-1".into(),
                prompt_id: "p-1".into(),
                state: BlockState::Resolved,
                schema_type: Some("FlightReservation".into()),
                content: Some(serde_json::json!({"@type": "FlightReservation"})),
                linked_block_ids: Vec::new(),
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
            }],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&canvas).unwrap();
        let back: Canvas = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "c-1");
        assert_eq!(back.name, "Flight to Tokyo");
        assert_eq!(back.blocks.len(), 1);
    }

    #[test]
    fn canvas_empty_blocks() {
        let canvas = Canvas {
            id: "c-empty".into(),
            name: "New Canvas".into(),
            blocks: Vec::new(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&canvas).unwrap();
        let back: Canvas = serde_json::from_str(&json).unwrap();
        assert!(back.blocks.is_empty());
    }

    // ── CanvasPrompt serde ────────────────────────────────

    #[test]
    fn canvas_prompt_roundtrip_json() {
        let prompt = CanvasPrompt {
            id: "p-1".into(),
            text: "Find me a flight to Tokyo".into(),
            reshape_block_id: None,
            canvas_id: "c-1".into(),
            submitted_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&prompt).unwrap();
        let back: CanvasPrompt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "p-1");
        assert_eq!(back.text, "Find me a flight to Tokyo");
        assert!(back.reshape_block_id.is_none());
    }

    #[test]
    fn canvas_prompt_with_reshape() {
        let prompt = CanvasPrompt {
            id: "p-2".into(),
            text: "Make it cheaper".into(),
            reshape_block_id: Some("blk-1".into()),
            canvas_id: "c-1".into(),
            submitted_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&prompt).unwrap();
        let back: CanvasPrompt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.reshape_block_id.as_deref(), Some("blk-1"));
    }

    // ── BlockEvent serde ──────────────────────────────────

    #[test]
    fn block_event_wraps_block() {
        let event = BlockEvent {
            block: CanvasBlock {
                id: "blk-ev".into(),
                prompt_id: "p-1".into(),
                state: BlockState::Resolved,
                schema_type: Some("Answer".into()),
                content: Some(serde_json::json!({"text": "42"})),
                linked_block_ids: Vec::new(),
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: BlockEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.block.id, "blk-ev");
        assert_eq!(back.block.schema_type.as_deref(), Some("Answer"));
    }

    // ── SetupState serde ──────────────────────────────────

    #[test]
    fn setup_state_roundtrip_json() {
        let state = SetupState {
            identity_created: true,
            llm_configured: false,
            setup_complete: false,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: SetupState = serde_json::from_str(&json).unwrap();
        assert!(back.identity_created);
        assert!(!back.llm_configured);
        assert!(!back.setup_complete);
    }

    // ── ScenarioCard serde ────────────────────────────────

    #[test]
    fn scenario_card_roundtrip_json() {
        let card = ScenarioCard {
            id: "search".into(),
            title: "Web Search".into(),
            description: "Search the web".into(),
            icon: "\u{1F50D}".into(),
            agent_name: "Web Search Agent".into(),
            action_type: "schema:SearchAction".into(),
            requires_disclosure: vec![],
            returns: vec!["schema:SearchResult".into()],
        };
        let json = serde_json::to_string(&card).unwrap();
        let back: ScenarioCard = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "search");
        assert!(back.requires_disclosure.is_empty());
        assert_eq!(back.returns, vec!["schema:SearchResult"]);
    }

    // ── OrchestratorStatus all variants ───────────────────

    #[test]
    fn status_unconfigured_roundtrip() {
        let status = OrchestratorStatus::Unconfigured;
        let json = serde_json::to_string(&status).unwrap();
        let back: OrchestratorStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn status_disconnected_roundtrip() {
        let status = OrchestratorStatus::Disconnected;
        let json = serde_json::to_string(&status).unwrap();
        let back: OrchestratorStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn status_offline_roundtrip() {
        let status = OrchestratorStatus::Offline;
        let json = serde_json::to_string(&status).unwrap();
        let back: OrchestratorStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    // ── RunResult serde ────────────────────────────────────

    #[test]
    fn run_result_roundtrip_json() {
        let result = RunResult {
            scenario_id: "search".into(),
            agent_name: "Web Search Agent".into(),
            steps: vec![StepResult {
                step_number: 1,
                step_name: "Discover agent".into(),
                status: "completed".into(),
                detail: Some("Found agent".into()),
                timestamp: "2026-01-01T00:00:00Z".into(),
            }],
            receipt: None,
            receipt_url: None,
            query: Some("test query".into()),
            search_results: None,
            completed_at: "2026-01-01T00:00:00Z".into(),
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: RunResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scenario_id, "search");
        assert!(back.success);
        assert_eq!(back.steps.len(), 1);
        assert_eq!(back.steps[0].step_number, 1);
    }

    // ── SearchResult serde ────────────────────────────────

    #[test]
    fn search_result_roundtrip_json() {
        let result = SearchResult {
            title: "Test Page".into(),
            url: "https://example.com".into(),
            snippet: "A test snippet".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: SearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, "Test Page");
        assert_eq!(back.url, "https://example.com");
    }

    // ── Identity types serde ──────────────────────────────

    #[test]
    fn identity_info_roundtrip_json() {
        let info = IdentityInfo {
            did: "did:pap:abc123".into(),
            public_key_b64: "dGVzdA".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: IdentityInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.did, "did:pap:abc123");
    }

    #[test]
    fn exported_key_roundtrip_json() {
        let key = ExportedKey {
            seed_b64: "dGVzdHNlZWQ".into(),
            did: "did:pap:abc123".into(),
            exported_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&key).unwrap();
        let back: ExportedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seed_b64, "dGVzdHNlZWQ");
    }

    #[test]
    fn successor_designation_roundtrip_json() {
        let succ = SuccessorDesignation {
            successor_did: "did:pap:new".into(),
            relationship: "heir".into(),
            notes: "My successor".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&succ).unwrap();
        let back: SuccessorDesignation = serde_json::from_str(&json).unwrap();
        assert_eq!(back.relationship, "heir");
    }

    #[test]
    fn key_backup_status_roundtrip_json() {
        let status = KeyBackupStatus { backed_up: true };
        let json = serde_json::to_string(&status).unwrap();
        let back: KeyBackupStatus = serde_json::from_str(&json).unwrap();
        assert!(back.backed_up);
    }

    // ── Pipeline types serde ──────────────────────────────

    #[test]
    fn pipeline_info_roundtrip_json() {
        let pipeline = PipelineInfo {
            id: "pipe-1".into(),
            name: "Test Pipeline".into(),
            nodes: vec![PipelineNodeInfo {
                id: "n-1".into(),
                agent_hash: "hash123".into(),
                agent_name: "Agent1".into(),
                position_x: 100.0,
                position_y: 200.0,
            }],
            edges: vec![PipelineEdgeInfo {
                from_node: "n-1".into(),
                to_node: "n-2".into(),
            }],
            created_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&pipeline).unwrap();
        let back: PipelineInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Test Pipeline");
        assert_eq!(back.nodes.len(), 1);
        assert_eq!(back.nodes[0].position_x, 100.0);
        assert_eq!(back.edges.len(), 1);
    }

    // ── RegistryInfo serde ────────────────────────────────

    #[test]
    fn registry_info_roundtrip_json() {
        let info = RegistryInfo {
            url: "pap://builtin".into(),
            agent_count: 5,
            peer_count: 3,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: RegistryInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url, "pap://builtin");
        assert_eq!(back.agent_count, 5);
    }

    // ── Receipt types serde ───────────────────────────────

    #[test]
    fn receipt_info_roundtrip_json() {
        let info = ReceiptInfo {
            session_id: "sess-1".into(),
            action: "schema:SearchAction".into(),
            initiator_did: "did:pap:init".into(),
            receiver_did: "did:pap:recv".into(),
            property_refs: vec!["schema:Person.name".into()],
            co_signed: true,
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: ReceiptInfo = serde_json::from_str(&json).unwrap();
        assert!(back.co_signed);
        assert_eq!(back.property_refs.len(), 1);
    }

    #[test]
    fn receipt_verification_roundtrip_json() {
        let result = ReceiptVerificationResult {
            session_id: "sess-1".into(),
            initiator_signature_valid: true,
            receiver_signature_valid: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: ReceiptVerificationResult = serde_json::from_str(&json).unwrap();
        assert!(back.initiator_signature_valid);
        assert!(!back.receiver_signature_valid);
    }
}
