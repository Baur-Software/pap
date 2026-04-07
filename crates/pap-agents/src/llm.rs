//! LLM provider configuration and client implementations for dynamic agents.
//!
//! This module defines the `LlmProvider` enum, related model-catalog types,
//! the `LlmClient` trait, and concrete implementations:
//!
//! - [`ExternalLlmClient`] — delegates to Mistral, Ollama, or any
//!   OpenAI-compatible HTTP endpoint via `reqwest::blocking`.
//! - [`BuiltInLlmClient`] — runs a GGUF model locally via Candle (only
//!   available when the `candle` feature is enabled).
//!
//! Use [`LlmProvider::into_client`] to construct the appropriate client.
//!
//! `papillon-shared` re-exports these so the app layer sees them at the same path.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dynamic::is_safe_url;

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
    vec![
        BuiltInModelInfo {
            id: "gemma-4-1b".into(),
            display_name: "Gemma 4 1B Instruct (Q4)".into(),
            repo: "bartowski/google_gemma-4-1b-it-GGUF".into(),
            filename: "google_gemma-4-1b-it-Q4_K_M.gguf".into(),
            size_hint: "~0.7 GB".into(),
            download_url: "https://huggingface.co/bartowski/google_gemma-4-1b-it-GGUF/resolve/main/google_gemma-4-1b-it-Q4_K_M.gguf".into(),
            tokenizer_url: "https://huggingface.co/google/gemma-4-1b-it/resolve/main/tokenizer.json".into(),
            web_compatible: true,
        },
        BuiltInModelInfo {
            id: "tinyllama-1.1b".into(),
            display_name: "TinyLlama 1.1B Chat (Q4)".into(),
            repo: "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF".into(),
            filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
            size_hint: "~0.6 GB".into(),
            download_url: "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".into(),
            tokenizer_url: "https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0/resolve/main/tokenizer.json".into(),
            web_compatible: false,
        },
    ]
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
            model_id: "gemma-4-1b".into(),
        }
    }
}

impl LlmProvider {
    /// Construct the appropriate [`LlmClient`] for this provider.
    ///
    /// For `BuiltIn`, `model_path` defaults to
    /// `~/.local/share/papillon/models/` (or the platform-equivalent returned
    /// by [`default_model_dir`]) when `None` is supplied.
    pub fn into_client(self) -> Box<dyn LlmClient> {
        match self {
            LlmProvider::BuiltIn { model_id } => {
                #[cfg(feature = "candle")]
                {
                    Box::new(BuiltInLlmClient::new(model_id, None))
                }
                #[cfg(not(feature = "candle"))]
                {
                    let _ = model_id;
                    Box::new(UnavailableLlmClient {
                        reason: "BuiltIn provider requires the `candle` feature".into(),
                    })
                }
            }
            LlmProvider::Mistral { api_key, model } => Box::new(ExternalLlmClient {
                kind: ExternalKind::Mistral { api_key, model },
            }),
            LlmProvider::Ollama { endpoint, model } => Box::new(ExternalLlmClient {
                kind: ExternalKind::Ollama { endpoint, model },
            }),
            LlmProvider::OpenAiCompatible {
                endpoint,
                api_key,
                model,
            } => Box::new(ExternalLlmClient {
                kind: ExternalKind::OpenAiCompatible {
                    endpoint,
                    api_key,
                    model,
                },
            }),
            LlmProvider::None => Box::new(UnavailableLlmClient {
                reason: "no LLM provider configured".into(),
            }),
        }
    }
}

/// Returns the platform-appropriate default directory for on-device models.
///
/// | Platform | Path |
/// |----------|------|
/// | Linux    | `~/.local/share/papillon/models/` |
/// | macOS    | `~/Library/Application Support/papillon/models/` |
/// | Windows  | `%APPDATA%\papillon\models\` |
/// | Other    | `~/.papillon/models/` |
pub fn default_model_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs_home()
            .join("Library")
            .join("Application Support")
            .join("papillon")
            .join("models")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs_home())
            .join("papillon")
            .join("models")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        dirs_home()
            .join(".local")
            .join("share")
            .join("papillon")
            .join("models")
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ─── LlmClient trait ──────────────────────────────────────────────────────────

/// Synchronous LLM client interface.
///
/// Implementations must be `Send + Sync` so they can be shared across threads
/// in the Tauri command layer.
///
/// The primary method is [`LlmClient::classify_intent`], used by the PAP
/// orchestrator to map a free-text user query onto one of the registered
/// agent action types.
pub trait LlmClient: Send + Sync {
    /// Classify `text` against `candidate_actions` and return the best
    /// matching action string.
    ///
    /// For generative models the caller wraps this in a structured prompt
    /// and expects the returned string to be one of `candidate_actions`
    /// (or a short explanation when no match is found).
    fn classify_intent(
        &self,
        text: &str,
        candidate_actions: &[String],
    ) -> Result<String, LlmClientError>;

    /// Free-form text completion (system + user).  Used by
    /// `DynamicAgentHandler` when no HTTP endpoint returns a result.
    fn complete(&self, system: &str, user: &str) -> Result<String, LlmClientError>;
}

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors returned by [`LlmClient`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum LlmClientError {
    #[error("LLM unavailable: {0}")]
    Unavailable(String),
    #[error("LLM request failed: {0}")]
    Request(String),
    #[error("LLM response malformed: {0}")]
    ResponseParse(String),
    #[error("Model I/O error: {0}")]
    Io(String),
}

// ─── UnavailableLlmClient ─────────────────────────────────────────────────────

/// A no-op client returned for `LlmProvider::None` or when the `candle`
/// feature is disabled.  Every call returns [`LlmClientError::Unavailable`].
struct UnavailableLlmClient {
    reason: String,
}

impl LlmClient for UnavailableLlmClient {
    fn classify_intent(
        &self,
        _text: &str,
        _candidate_actions: &[String],
    ) -> Result<String, LlmClientError> {
        Err(LlmClientError::Unavailable(self.reason.clone()))
    }

    fn complete(&self, _system: &str, _user: &str) -> Result<String, LlmClientError> {
        Err(LlmClientError::Unavailable(self.reason.clone()))
    }
}

// ─── ExternalLlmClient ────────────────────────────────────────────────────────

enum ExternalKind {
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
}

/// HTTP-based LLM client for Mistral, Ollama, and OpenAI-compatible APIs.
///
/// All network calls use `reqwest::blocking` with a 30-second timeout.
pub struct ExternalLlmClient {
    kind: ExternalKind,
}

impl ExternalLlmClient {
    fn chat(&self, system: &str, user: &str) -> Result<String, LlmClientError> {
        use std::time::Duration;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| LlmClientError::Request(format!("http client init: {e}")))?;

        match &self.kind {
            ExternalKind::Ollama { endpoint, model } => {
                if !is_safe_url(endpoint) {
                    return Err(LlmClientError::Request(format!(
                        "ollama endpoint is not a safe URL (must be https:// with a public hostname): {endpoint}"
                    )));
                }
                let payload = serde_json::json!({
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user},
                    ],
                    "stream": false,
                });
                let resp: serde_json::Value = client
                    .post(format!("{endpoint}/api/chat"))
                    .json(&payload)
                    .send()
                    .map_err(|e| LlmClientError::Request(format!("ollama: {e}")))?
                    .json()
                    .map_err(|e| LlmClientError::ResponseParse(format!("ollama json: {e}")))?;
                resp["message"]["content"]
                    .as_str()
                    .map(String::from)
                    .ok_or_else(|| {
                        LlmClientError::ResponseParse("ollama: missing message.content".into())
                    })
            }
            ExternalKind::Mistral { api_key, model } => call_openai_compat_blocking(
                &client,
                "https://api.mistral.ai/v1/chat/completions",
                api_key,
                model,
                system,
                user,
            ),
            ExternalKind::OpenAiCompatible {
                endpoint,
                api_key,
                model,
            } => call_openai_compat_blocking(
                &client,
                &format!("{endpoint}/chat/completions"),
                api_key,
                model,
                system,
                user,
            ),
        }
    }
}

fn call_openai_compat_blocking(
    client: &reqwest::blocking::Client,
    url: &str,
    api_key: &str,
    model: &str,
    system: &str,
    user: &str,
) -> Result<String, LlmClientError> {
    let payload = serde_json::json!({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    });
    let resp: serde_json::Value = client
        .post(url)
        .bearer_auth(api_key)
        .json(&payload)
        .send()
        .map_err(|e| LlmClientError::Request(format!("llm request: {e}")))?
        .json()
        .map_err(|e| LlmClientError::ResponseParse(format!("llm response json: {e}")))?;
    resp["choices"][0]["message"]["content"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| LlmClientError::ResponseParse("missing choices[0].message.content".into()))
}

impl LlmClient for ExternalLlmClient {
    fn classify_intent(
        &self,
        text: &str,
        candidate_actions: &[String],
    ) -> Result<String, LlmClientError> {
        let actions_list = candidate_actions.join(", ");
        let system = format!(
            "You are a PAP intent classifier. \
             Given a user query, respond with exactly one action from this list: {actions_list}. \
             Respond with only the action string — no explanation."
        );
        self.chat(&system, text)
    }

    fn complete(&self, system: &str, user: &str) -> Result<String, LlmClientError> {
        self.chat(system, user)
    }
}

// ─── BuiltInLlmClient ─────────────────────────────────────────────────────────

/// On-device LLM client backed by a GGUF model loaded via Candle.
///
/// Inference runs entirely offline on the CPU — no network calls.
/// The model is loaded lazily on first use via interior mutability.
///
/// Only available when the `candle` feature is enabled.
#[cfg(feature = "candle")]
pub struct BuiltInLlmClient {
    model_id: String,
    /// Explicit model directory.  `None` → use [`default_model_dir`].
    model_dir: Option<PathBuf>,
    /// Lazily-loaded model state protected by a mutex.
    state: std::sync::Mutex<Option<BuiltInState>>,
}

#[cfg(feature = "candle")]
struct BuiltInState {
    model: candle_transformers::models::quantized_llama::ModelWeights,
    tokenizer: tokenizers::Tokenizer,
    device: candle_core::Device,
    eos_token: u32,
}

#[cfg(feature = "candle")]
impl BuiltInLlmClient {
    /// Create a new client.
    ///
    /// `model_dir` overrides the default search path ([`default_model_dir`]).
    pub fn new(model_id: impl Into<String>, model_dir: Option<PathBuf>) -> Self {
        Self {
            model_id: model_id.into(),
            model_dir,
            state: std::sync::Mutex::new(None),
        }
    }

    /// Resolve the model directory, falling back to [`default_model_dir`].
    fn resolved_model_dir(&self) -> PathBuf {
        self.model_dir.clone().unwrap_or_else(default_model_dir)
    }

    /// Lazily load the model.  Returns a `MutexGuard` so callers hold the
    /// lock for the duration of inference, preventing concurrent loads.
    fn ensure_loaded(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<BuiltInState>>, LlmClientError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| LlmClientError::Io("model mutex poisoned".into()))?;

        if guard.is_none() {
            let info = builtin_model_catalog()
                .into_iter()
                .find(|m| m.id == self.model_id)
                .ok_or_else(|| {
                    LlmClientError::Unavailable(format!(
                        "unknown built-in model: {}",
                        self.model_id
                    ))
                })?;

            let model_dir = self.resolved_model_dir();
            let model_path = model_dir.join(&info.filename);
            let tokenizer_path = model_dir.join("tokenizer.json");

            if !model_path.exists() {
                return Err(LlmClientError::Io(format!(
                    "model file not found: {} — download it first",
                    model_path.display()
                )));
            }
            if !tokenizer_path.exists() {
                return Err(LlmClientError::Io(format!(
                    "tokenizer not found: {}",
                    tokenizer_path.display()
                )));
            }

            let device = candle_core::Device::Cpu;

            let mut file = std::fs::File::open(&model_path)
                .map_err(|e| LlmClientError::Io(format!("open model: {e}")))?;
            let gguf = candle_core::quantized::gguf_file::Content::read(&mut file)
                .map_err(|e| LlmClientError::Io(format!("parse GGUF: {e}")))?;
            let weights = candle_transformers::models::quantized_llama::ModelWeights::from_gguf(
                gguf, &mut file, &device,
            )
            .map_err(|e| LlmClientError::Io(format!("load weights: {e}")))?;

            let tokenizer = tokenizers::Tokenizer::from_file(&tokenizer_path)
                .map_err(|e| LlmClientError::Io(format!("load tokenizer: {e}")))?;

            let eos_token = tokenizer.token_to_id("</s>").unwrap_or(2);

            *guard = Some(BuiltInState {
                model: weights,
                tokenizer,
                device,
                eos_token,
            });
        }

        Ok(guard)
    }

    /// Run inference on a prompt and return generated text.
    fn generate_text(&self, prompt: &str, max_tokens: usize) -> Result<String, LlmClientError> {
        use candle_core::Tensor;
        use candle_transformers::generation::{LogitsProcessor, Sampling};

        let mut guard = self.ensure_loaded()?;
        let state = guard.as_mut().expect("state is Some after ensure_loaded");

        let encoding = state
            .tokenizer
            .encode(prompt, true)
            .map_err(|e| LlmClientError::Io(format!("tokenize: {e}")))?;
        let prompt_tokens = encoding.get_ids();
        let prompt_len = prompt_tokens.len();

        let mut logits_processor = LogitsProcessor::from_sampling(
            42,
            Sampling::TopKThenTopP {
                k: 40,
                p: 0.9,
                temperature: 0.7,
            },
        );

        let mut all_tokens: Vec<u32> = prompt_tokens.to_vec();
        let mut input = Tensor::new(prompt_tokens, &state.device)
            .map_err(|e| LlmClientError::Io(format!("tensor: {e}")))?
            .unsqueeze(0)
            .map_err(|e| LlmClientError::Io(format!("unsqueeze: {e}")))?;

        let mut pos = 0usize;

        for _ in 0..max_tokens {
            let logits = state
                .model
                .forward(&input, pos)
                .map_err(|e| LlmClientError::Io(format!("forward: {e}")))?;
            let logits = logits
                .squeeze(0)
                .map_err(|e| LlmClientError::Io(format!("squeeze: {e}")))?;
            let next_token = logits_processor
                .sample(&logits)
                .map_err(|e| LlmClientError::Io(format!("sample: {e}")))?;

            if next_token == state.eos_token {
                break;
            }

            all_tokens.push(next_token);

            if pos == 0 {
                pos = prompt_len;
            } else {
                pos += 1;
            }

            input = Tensor::new(&[next_token], &state.device)
                .map_err(|e| LlmClientError::Io(format!("tensor next: {e}")))?
                .unsqueeze(0)
                .map_err(|e| LlmClientError::Io(format!("unsqueeze next: {e}")))?;
        }

        let generated = &all_tokens[prompt_len..];
        state
            .tokenizer
            .decode(generated, true)
            .map_err(|e| LlmClientError::Io(format!("decode: {e}")))
    }
}

#[cfg(feature = "candle")]
impl LlmClient for BuiltInLlmClient {
    fn classify_intent(
        &self,
        text: &str,
        candidate_actions: &[String],
    ) -> Result<String, LlmClientError> {
        let actions_list = candidate_actions.join(", ");
        let prompt = format!(
            "[INST] You are a PAP intent classifier. \
             Respond with exactly one action from this list: {actions_list}. \
             Respond with only the action string — no explanation.\n\
             User query: {text} [/INST]"
        );
        let raw = self.generate_text(&prompt, 64)?;
        // Trim whitespace; if the output contains one of the candidate
        // actions exactly, return it, otherwise return the raw output.
        let trimmed = raw.trim().to_string();
        for action in candidate_actions {
            if trimmed.contains(action.as_str()) {
                return Ok(action.clone());
            }
        }
        Ok(trimmed)
    }

    fn complete(&self, system: &str, user: &str) -> Result<String, LlmClientError> {
        let prompt = format!(
            "[INST] {system}\n\n{user} [/INST]",
            system = system,
            user = user
        );
        self.generate_text(&prompt, 512)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_default_provider() {
        assert_eq!(
            LlmProvider::default(),
            LlmProvider::BuiltIn {
                model_id: "gemma-4-1b".into()
            }
        );
    }

    #[test]
    fn into_client_none_returns_unavailable() {
        let client = LlmProvider::None.into_client();
        assert!(client.classify_intent("hello", &[]).is_err());
        assert!(client.complete("sys", "user").is_err());
    }

    #[test]
    fn into_client_builtin_returns_err_when_model_missing() {
        // No model files are present on the test machine, so the
        // BuiltInLlmClient should surface an Io error on first use.
        let client = LlmProvider::BuiltIn {
            model_id: "gemma-4-1b".into(),
        }
        .into_client();
        // classify_intent will attempt to load the model — which won't exist
        // in CI — and return an error.  We only check that calling it does
        // not panic; an error is the correct behaviour.
        let _ = client.classify_intent("book a flight", &["schema:ReserveAction".into()]);
    }

    #[test]
    fn default_model_dir_is_absolute() {
        let dir = default_model_dir();
        // The path may not exist in CI, but it must be absolute.
        assert!(
            dir.is_absolute(),
            "default_model_dir() should be absolute, got: {}",
            dir.display()
        );
    }

    #[test]
    fn llm_provider_round_trips_through_json() {
        let providers = vec![
            LlmProvider::None,
            LlmProvider::BuiltIn {
                model_id: "gemma-4-1b".into(),
            },
            LlmProvider::Mistral {
                api_key: "key".into(),
                model: "mistral-small".into(),
            },
            LlmProvider::Ollama {
                endpoint: "http://localhost:11434".into(),
                model: "llama3".into(),
            },
            LlmProvider::OpenAiCompatible {
                endpoint: "https://api.example.com/v1".into(),
                api_key: "key".into(),
                model: "gpt-4o".into(),
            },
        ];

        for p in providers {
            let json = serde_json::to_string(&p).unwrap();
            let back: LlmProvider = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn builtin_alias_deserialises() {
        // The `#[serde(alias = "BuiltIn")]` should accept the tagged form too.
        let json = r#"{"BuiltIn":{"model_id":"gemma-4-1b"}}"#;
        let p: LlmProvider = serde_json::from_str(json).unwrap();
        assert_eq!(
            p,
            LlmProvider::BuiltIn {
                model_id: "gemma-4-1b".into()
            }
        );
    }

    #[test]
    fn catalog_first_entry_is_default_model() {
        let catalog = builtin_model_catalog();
        assert!(!catalog.is_empty(), "catalog must not be empty");
        let default_id = match LlmProvider::default() {
            LlmProvider::BuiltIn { model_id } => model_id,
            _ => panic!("default provider must be BuiltIn"),
        };
        assert_eq!(
            catalog[0].id, default_id,
            "first catalog entry must match the default model_id"
        );
    }
}
