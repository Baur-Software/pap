use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// LLM provider types: on native, re-export from pap-agents (single source of truth).
// On WASM, pap-agents pulls in reqwest::blocking → tokio → mio which does not compile
// for wasm32-unknown-unknown, so we define the types inline here.
#[cfg(feature = "native")]
pub use pap_agents::{
    builtin_model_catalog, BuiltInModelInfo, LlmProvider, ModelAvailability, ModelDownloadProgress,
};

#[cfg(not(feature = "native"))]
pub use llm_types::{
    builtin_model_catalog, BuiltInModelInfo, LlmProvider, ModelAvailability, ModelDownloadProgress,
};

#[cfg(not(feature = "native"))]
mod llm_types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct BuiltInModelInfo {
        pub id: String,
        pub display_name: String,
        pub repo: String,
        pub filename: String,
        pub size_hint: String,
        pub download_url: String,
        pub tokenizer_url: String,
        pub web_compatible: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ModelAvailability {
        pub model_id: String,
        pub model_present: bool,
        pub tokenizer_present: bool,
        pub ready: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ModelDownloadProgress {
        pub model_id: String,
        pub file_type: String,
        pub downloaded_bytes: u64,
        pub total_bytes: u64,
        pub progress_pct: u8,
    }

    pub fn builtin_model_catalog() -> Vec<BuiltInModelInfo> {
        vec![BuiltInModelInfo {
            id: "tinyllama-1.1b".into(),
            display_name: "TinyLlama 1.1B Chat (Q4)".into(),
            repo: "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF".into(),
            filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
            size_hint: "~0.6 GB".into(),
            download_url: "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
            tokenizer_url: "https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0/resolve/main/tokenizer.json".into(),
            web_compatible: false,
        }]
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub enum LlmProvider {
        #[serde(alias = "BuiltIn")]
        BuiltIn {
            model_id: String,
        },
        Mistral {
            api_key: String,
            model: String,
        },
        Ollama {
            endpoint: String,
            model: String,
        },
        OpenAiCompatible {
            endpoint: String,
            api_key: String,
            model: String,
        },
        None,
    }

    impl Default for LlmProvider {
        fn default() -> Self {
            LlmProvider::BuiltIn {
                model_id: "tinyllama-1.1b".into(),
            }
        }
    }
}

/// Principal identity information (never contains private keys).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub did: String,
    pub public_key_b64: String,
    pub created_at: String,
}

/// Profile metadata — represents a saved user profile with isolated identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used: Option<String>,
    pub active: bool,
}

/// Summary of a connected registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInfo {
    pub url: String,
    pub agent_count: usize,
    pub peer_count: usize,
}

/// Agent information for display in the registry browser and agent management UI.
/// This is the safe frontend-facing type — never contains operator_key_seed,
/// HttpEndpointConfig, llm_instructions, or endpoint internals.
///
/// An agent is defined entirely by its contract: the mandate it accepts and the
/// schema type it returns. Transport and execution environment are implementation
/// details — `endpoint` encodes them implicitly (None = local, Some(url) = remote,
/// with the URL scheme distinguishing HTTP from WebSocket).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub provider_name: String,
    pub provider_did: String,
    pub capabilities: Vec<String>,
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    /// Transport endpoint. None = local agent (embedded component or on-device).
    /// Some(url) = remote agent; URL scheme implies transport (https vs wss).
    pub endpoint: Option<String>,
    pub content_hash: String,
    /// The agent's DID (did:key:z...). None for remote registry agents.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// Origin: "compiled", "catalog", "user_created", or "generated".
    #[serde(default)]
    pub source: String,
    /// Registry URLs this agent's advertisement has been published to.
    #[serde(default)]
    pub published_to: Vec<String>,
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

/// The type of a pipeline node — either a remote agent or an on-device synthesizer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineNodeType {
    /// Standard agent node — executes a PAP handshake.
    #[default]
    Agent,
    /// On-device synthesizer — merges upstream results into an outcome block.
    /// Never leaves the device; runs the local LLM (Candle/TinyLlama).
    Synthesizer,
}

/// A node in a pipeline (represents an agent or synthesizer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineNodeInfo {
    pub id: String,
    pub agent_hash: String,
    pub agent_name: String,
    /// The schema.org action this node performs (e.g. "schema:SearchAction").
    #[serde(default)]
    pub action_type: String,
    /// Node type: "agent" (default) or "synthesizer".
    #[serde(default)]
    pub node_type: PipelineNodeType,
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
    Downloading {
        progress_pct: u8,
    },
    /// Model loaded, ready for inference.
    Ready,
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
    /// Planning phase — agent identified but not yet executed.
    /// Shows as a dashed outline with mandate scope preview.
    Ghost {
        agent_name: String,
        action_type: String,
        /// Properties this agent will need to see.
        disclosure_preview: Vec<String>,
        /// Schema types this agent will return.
        returns_preview: Vec<String>,
    },
    /// Handshake in progress — `phase` is 1..=6.
    Resolving { phase: u8, phase_label: String },
    /// Handshake completed, JSON-LD content available.
    Resolved,
    /// Handshake failed at a specific phase.
    Failed { phase: u8, reason: String },
    /// Synthesized outcome — wraps multiple agent results into a single
    /// user-facing answer. The provenance layer underneath shows individual
    /// agent blocks with their mandate scopes and receipts.
    Outcome {
        /// Block IDs of the agent blocks that contributed to this outcome.
        provenance_block_ids: Vec<String>,
    },
}

/// A single block on the Papillon canvas.
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
    /// The original user prompt text. Stored for retry support.
    #[serde(default)]
    pub prompt_text: Option<String>,
    /// Current lifecycle state.
    pub state: BlockState,
    /// Schema.org `@type` from the JSON-LD response (e.g. "FlightReservation").
    /// `None` while resolving.
    pub schema_type: Option<String>,
    /// Raw JSON-LD content returned by the agent. `None` while resolving.
    pub content: Option<serde_json::Value>,
    /// IDs of semantically linked blocks (same prompt, related data).
    pub linked_block_ids: Vec<String>,
    /// DID of the agent that owns this block. Used by the renderer to select
    /// agent-scoped templates over global schema-type renderers.
    #[serde(default)]
    pub agent_did: Option<String>,
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

// ── Scenario runner types ────────────────────────────────

/// Result of running a scenario through the full 6-step handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioRunResult {
    pub scenario_id: String,
    pub agent_name: String,
    pub steps: Vec<ScenarioStepResult>,
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
pub struct ScenarioStepResult {
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

// ── Template types for user-defined renderers ─────────────────────

/// Layout configuration for template rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutConfig {
    /// "grid" or "flex"
    pub r#type: String,
    /// Number of columns for grid layout
    pub columns: Option<i32>,
    /// Direction for flex layout: "row" or "column"
    pub direction: Option<String>,
    /// Spacing: "sm", "md", "lg"
    pub spacing: Option<String>,
}

/// Condition for conditional field rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Condition {
    /// Field path to check (e.g., "name", "offers.price")
    pub field: String,
    /// Operation: "exists", "equals", "contains"
    pub op: String,
    /// Optional value for comparison
    pub value: Option<String>,
}

/// Styling configuration for a field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StyleConfig {
    /// CSS class name for styling
    pub class_name: Option<String>,
    /// Hex color override
    pub color: Option<String>,
}

/// Field mapping in a template.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldMapping {
    /// JSON path to extract from content (e.g., "name", "offers.0.price")
    pub path: String,
    /// Display label for the field
    pub label: Option<String>,
    /// Display type: "title", "text", "price", "date", "url"
    pub display: String,
    /// Optional condition for rendering
    pub condition: Option<Condition>,
    /// Optional styling
    pub style: Option<StyleConfig>,
}

/// Declarative template configuration for rendering JSON-LD content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemplateConfig {
    /// Schema version for forward compatibility
    pub version: i32,
    /// Layout directives
    pub layout: LayoutConfig,
    /// Ordered list of fields to render
    pub fields: Vec<FieldMapping>,
}

impl TemplateConfig {
    /// Validate template configuration for schema compliance and consistency.
    /// Returns an error message if validation fails, or Ok(()) if valid.
    pub fn validate(&self) -> Result<(), String> {
        // Version must be >= 1
        if self.version < 1 {
            return Err("Template version must be >= 1".to_string());
        }

        // Layout type must be "grid" or "flex"
        if !["grid", "flex"].contains(&self.layout.r#type.as_str()) {
            return Err("Layout type must be 'grid' or 'flex'".to_string());
        }

        // Grid layout: columns must be > 0
        if self.layout.r#type == "grid" {
            if let Some(cols) = self.layout.columns {
                if cols <= 0 {
                    return Err("Grid layout must have columns > 0".to_string());
                }
            } else {
                return Err("Grid layout requires columns to be set".to_string());
            }
        }

        // Flex layout: direction must be "row" or "column" if specified
        if self.layout.r#type == "flex" {
            if let Some(dir) = &self.layout.direction {
                if !["row", "column"].contains(&dir.as_str()) {
                    return Err("Flex layout direction must be 'row' or 'column'".to_string());
                }
            }
        }

        // Fields list must not be empty
        if self.fields.is_empty() {
            return Err("Template must have at least one field".to_string());
        }

        // Validate each field
        let valid_displays = ["title", "text", "price", "date", "url"];
        for field in &self.fields {
            // Path must not be empty
            if field.path.trim().is_empty() {
                return Err("Field path cannot be empty".to_string());
            }

            // Display type must be valid
            if !valid_displays.contains(&field.display.as_str()) {
                return Err(format!(
                    "Invalid display type '{}'. Must be one of: {}",
                    field.display,
                    valid_displays.join(", ")
                ));
            }

            // Validate condition if present
            if let Some(condition) = &field.condition {
                if condition.field.trim().is_empty() {
                    return Err("Condition field cannot be empty".to_string());
                }
                let valid_ops = ["exists", "equals", "contains"];
                if !valid_ops.contains(&condition.op.as_str()) {
                    return Err(format!(
                        "Invalid condition operator '{}'. Must be one of: {}",
                        condition.op,
                        valid_ops.join(", ")
                    ));
                }
            }
        }

        Ok(())
    }
}

/// User-defined template for rendering blocks with a specific schema type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    /// Unique template identifier (UUID)
    pub id: String,
    /// User-facing template name (unique)
    pub template_name: String,
    /// Schema.org type this template handles (e.g., "FlightReservation")
    pub schema_type: String,
    /// Optional DID for per-profile templates. None = global template.
    pub principal_did: Option<String>,
    /// Optional agent DID to scope this template to a specific agent's output.
    /// When set, this template is registered as an agent-scoped override and
    /// takes priority over any global renderer for the same schema_type.
    #[serde(default)]
    pub agent_did: Option<String>,
    /// Declarative template configuration
    pub template_config: TemplateConfig,
    /// Template version for schema evolution
    pub version: i32,
    /// Whether this template is currently enabled
    pub enabled: bool,
    /// ISO-8601 creation timestamp
    pub created_at: String,
    /// ISO-8601 last update timestamp
    pub updated_at: String,
    /// DID of the user who created this template
    pub created_by: Option<String>,
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
    fn catalog_default_is_tinyllama() {
        let catalog = builtin_model_catalog();
        assert_eq!(catalog[0].id, "tinyllama-1.1b");
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
    fn llm_provider_default_is_builtin_tinyllama() {
        let provider = LlmProvider::default();
        match &provider {
            LlmProvider::BuiltIn { model_id } => {
                assert_eq!(model_id, "tinyllama-1.1b");
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
            download_url: "https://example.com/test.gguf".into(),
            tokenizer_url: "https://example.com/tokenizer.json".into(),
            web_compatible: false,
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
            prompt_text: None,
            state: BlockState::Resolving {
                phase: 2,
                phase_label: "Issuing mandate...".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            agent_did: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: CanvasBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "blk-1");
        assert_eq!(back.prompt_id, "p-1");
        assert!(back.prompt_text.is_none());
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
            prompt_text: None,
            state: BlockState::Resolved,
            schema_type: Some("FlightReservation".into()),
            content: Some(content.clone()),
            linked_block_ids: vec!["blk-3".into()],
            agent_did: None,
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
            prompt_text: None,
            state: BlockState::Failed {
                phase: 5,
                reason: "Receipt co-sign rejected".into(),
            },
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            agent_did: None,
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
                prompt_text: None,
                state: BlockState::Resolved,
                schema_type: Some("FlightReservation".into()),
                content: Some(serde_json::json!({"@type": "FlightReservation"})),
                linked_block_ids: Vec::new(),
                agent_did: None,
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
                prompt_text: None,
                state: BlockState::Resolved,
                schema_type: Some("Answer".into()),
                content: Some(serde_json::json!({"text": "42"})),
                linked_block_ids: Vec::new(),
                agent_did: None,
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

    // ── ScenarioRunResult serde ───────────────────────────

    #[test]
    fn scenario_run_result_roundtrip_json() {
        let result = ScenarioRunResult {
            scenario_id: "search".into(),
            agent_name: "Web Search Agent".into(),
            steps: vec![ScenarioStepResult {
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
        let back: ScenarioRunResult = serde_json::from_str(&json).unwrap();
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
                action_type: "schema:SearchAction".into(),
                node_type: PipelineNodeType::default(),
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
    fn template_config_roundtrip_json() {
        let config = TemplateConfig {
            version: 1,
            layout: LayoutConfig {
                r#type: "grid".into(),
                columns: Some(2),
                direction: None,
                spacing: Some("md".into()),
            },
            fields: vec![FieldMapping {
                path: "name".into(),
                label: Some("Name".into()),
                display: "title".into(),
                condition: None,
                style: None,
            }],
        };
        let json = serde_json::to_string(&config).unwrap();
        let back: TemplateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.fields.len(), 1);
    }

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

    // ── CanvasBlock prompt_text ──────────────────────────────

    #[test]
    fn canvas_block_prompt_text_roundtrip() {
        let block = CanvasBlock {
            id: "blk-pt".into(),
            prompt_id: "p-1".into(),
            prompt_text: Some("search for Rust".into()),
            state: BlockState::Resolved,
            schema_type: None,
            content: None,
            linked_block_ids: Vec::new(),
            agent_did: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_string(&block).unwrap();
        let back: CanvasBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(back.prompt_text.as_deref(), Some("search for Rust"));
    }

    #[test]
    fn canvas_block_missing_prompt_text_deserializes_as_none() {
        // Simulate JSON from an older version that lacks the prompt_text field
        let json = r#"{
            "id": "blk-old",
            "prompt_id": "p-1",
            "state": "Resolved",
            "schema_type": null,
            "content": null,
            "linked_block_ids": [],
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }"#;
        let back: CanvasBlock = serde_json::from_str(json).unwrap();
        assert!(back.prompt_text.is_none());
    }

    // ── PipelineNodeInfo action_type backward compat ─────────

    #[test]
    fn pipeline_node_missing_action_type_deserializes_as_empty() {
        let json = r#"{
            "id": "n-1",
            "agent_hash": "h1",
            "agent_name": "Agent",
            "position_x": 0.0,
            "position_y": 0.0
        }"#;
        let back: PipelineNodeInfo = serde_json::from_str(json).unwrap();
        assert!(back.action_type.is_empty());
    }
}

// ── Shamir Secret Sharing recovery types ────────────────────

/// A single Shamir shard ready for distribution to a trustee.
///
/// `shard_json` is the JSON blob the trustee stores (a serialized `RecoveryShard`).
/// The frontend should prompt the user to save this to a file or password manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryShardInfo {
    /// 1-based index, unique within the ceremony.
    pub index: u8,
    /// Minimum shards required to reconstruct (M).
    pub threshold: u8,
    /// Total shards produced (N).
    pub total: u8,
    /// Serialized shard JSON for distribution to the trustee at this index.
    pub shard_json: String,
    /// DID of the principal whose seed was split.
    pub principal_did: String,
}

impl Drop for RecoveryShardInfo {
    fn drop(&mut self) {
        // shard_json contains the full serialized RecoveryShard including partial
        // secret material. Zeroize before the heap allocation is released.
        self.shard_json.zeroize();
    }
}

/// Result returned by `create_recovery_shards`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySetupResult {
    /// One entry per trustee (N entries total).
    pub shards: Vec<RecoveryShardInfo>,
    /// Public shard manifest JSON for publishing alongside the recovery mandate.
    pub manifest_json: String,
    /// DID of the principal whose seed was split.
    pub principal_did: String,
}

/// Result returned by `reconstruct_from_shards`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReconstructResult {
    /// The DID derived from the reconstructed seed.
    pub did: String,
    /// Base64url-encoded public key of the reconstructed identity.
    pub public_key_b64: String,
}

/// Persistent recovery configuration status returned by `get_recovery_status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStatus {
    /// `true` once the user has completed the Shamir shard setup ceremony.
    pub configured: bool,
}
