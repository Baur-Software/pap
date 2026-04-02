//! LLM provider configuration for dynamic agents.
//!
//! This module defines the `LlmProvider` enum and related model-catalog types.
//! `papillon-shared` re-exports these so the app layer sees them at the same path.

use serde::{Deserialize, Serialize};

/// Known built-in models that ship with (or can be downloaded by) Papillon.
/// Each entry maps to a GGUF file in either the bundled resources or the
/// user-writable data directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BuiltInModelInfo {
    pub id: String,
    pub display_name: String,
    /// HuggingFace repo this was sourced from (for attribution).
    pub repo: String,
    /// GGUF filename inside the `models/` directory.
    pub filename: String,
    pub size_hint: String,
    /// Direct download URL for the GGUF weights file.
    pub download_url: String,
    /// Direct download URL for the tokenizer.json file.
    pub tokenizer_url: String,
    /// Whether this model is small enough to run in-browser via WASM.
    pub web_compatible: bool,
}

/// Availability status of a built-in model on the local filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelAvailability {
    pub model_id: String,
    pub model_present: bool,
    pub tokenizer_present: bool,
    /// Both files present and ready to load.
    pub ready: bool,
}

/// Emitted during model file download for progress tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelDownloadProgress {
    pub model_id: String,
    /// Which file is being downloaded: "model" or "tokenizer".
    pub file_type: String,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub progress_pct: u8,
}

/// Catalog of models available for on-device inference.
/// The first entry is the default.
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

/// LLM provider for the orchestrator.
///
/// The default is `BuiltIn` with TinyLlama — inference runs locally via Candle
/// with no HTTP calls, which is the intended PAP architecture. External API
/// options (Mistral, Ollama, OpenAI-compatible) work over HTTP but disclose
/// orchestrator context to third parties.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LlmProvider {
    /// On-device inference via Candle. Model ships bundled with the app
    /// and runs entirely offline — no network calls.
    #[serde(alias = "BuiltIn")]
    BuiltIn { model_id: String },
    /// Mistral API — first-class support for Mistral's OpenAI-compatible
    /// endpoint at api.mistral.ai. Requires an API key.
    Mistral { api_key: String, model: String },
    /// External Ollama instance (requires HTTP). Use only if you already
    /// run Ollama and understand the privacy trade-off.
    Ollama { endpoint: String, model: String },
    /// Any OpenAI-compatible HTTP API (requires network + API key).
    OpenAiCompatible {
        endpoint: String,
        api_key: String,
        model: String,
    },
    /// No LLM configured.
    None,
}

impl Default for LlmProvider {
    fn default() -> Self {
        LlmProvider::BuiltIn {
            model_id: "tinyllama-1.1b".into(),
        }
    }
}
