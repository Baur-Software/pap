//! On-device LLM inference via Candle.
//!
//! Downloads GGUF models from HuggingFace Hub on first use, then runs
//! inference entirely offline — no HTTP calls, no data exfiltration.
//! This is the intended PAP architecture: the orchestrator decomposes
//! user queries into tool calls without ever touching the network.

use std::path::PathBuf;

use candle_core::quantized::gguf_file;
use candle_core::{Device, Tensor};
use candle_transformers::generation::{LogitsProcessor, Sampling};
use candle_transformers::models::quantized_llama as model;
use tokenizers::Tokenizer;

use papillion_shared::{builtin_model_catalog, BuiltInModelInfo};

/// A loaded model ready for inference.
pub struct LoadedModel {
    pub info: BuiltInModelInfo,
    pub model: model::ModelWeights,
    pub tokenizer: Tokenizer,
    pub device: Device,
}

/// Resolve a model_id to its catalog entry.
pub fn resolve_model(model_id: &str) -> Option<BuiltInModelInfo> {
    builtin_model_catalog()
        .into_iter()
        .find(|m| m.id == model_id)
}

/// Download the GGUF weights file from HuggingFace Hub.
/// Returns the local path to the cached file. Subsequent calls are instant.
pub async fn download_model(info: &BuiltInModelInfo) -> Result<PathBuf, String> {
    let repo = info.repo.clone();
    let filename = info.filename.clone();

    // hf-hub's sync API handles caching internally
    tokio::task::spawn_blocking(move || {
        let api = hf_hub::api::sync::Api::new().map_err(|e| format!("HF Hub init: {e}"))?;
        let repo = api.model(repo);
        let path = repo
            .get(&filename)
            .map_err(|e| format!("Model download: {e}"))?;
        Ok(path)
    })
    .await
    .map_err(|e| format!("Spawn: {e}"))?
}

/// Download the tokenizer for a model. Falls back to the model repo's
/// tokenizer.json, then to the base Mistral tokenizer.
pub async fn download_tokenizer(info: &BuiltInModelInfo) -> Result<PathBuf, String> {
    let repo = info.repo.clone();

    tokio::task::spawn_blocking(move || {
        let api = hf_hub::api::sync::Api::new().map_err(|e| format!("HF Hub init: {e}"))?;

        // Try the model repo first
        let model_repo = api.model(repo);
        if let Ok(path) = model_repo.get("tokenizer.json") {
            return Ok(path);
        }

        // Fall back to the base Mistral tokenizer
        let base = api.model("mistralai/Mistral-7B-Instruct-v0.2".into());
        base.get("tokenizer.json")
            .map_err(|e| format!("Tokenizer download: {e}"))
    })
    .await
    .map_err(|e| format!("Spawn: {e}"))?
}

/// Load a downloaded GGUF model into memory, ready for inference.
pub fn load_model(
    model_path: &PathBuf,
    tokenizer_path: &PathBuf,
) -> Result<LoadedModel, String> {
    let device = Device::Cpu;

    // Load GGUF
    let mut file =
        std::fs::File::open(model_path).map_err(|e| format!("Open model: {e}"))?;
    let gguf = gguf_file::Content::read(&mut file)
        .map_err(|e| format!("Parse GGUF: {e}"))?;
    let weights = model::ModelWeights::from_gguf(gguf, &mut file, &device)
        .map_err(|e| format!("Load weights: {e}"))?;

    // Load tokenizer
    let tokenizer = Tokenizer::from_file(tokenizer_path)
        .map_err(|e| format!("Load tokenizer: {e}"))?;

    Ok(LoadedModel {
        info: BuiltInModelInfo {
            id: String::new(),
            display_name: String::new(),
            repo: String::new(),
            filename: String::new(),
            size_hint: String::new(),
        },
        model: weights,
        tokenizer,
        device,
    })
}

/// Run text generation on a loaded model.
pub fn generate(
    loaded: &mut LoadedModel,
    prompt: &str,
    max_tokens: usize,
) -> Result<String, String> {
    let encoding = loaded
        .tokenizer
        .encode(prompt, true)
        .map_err(|e| format!("Tokenize: {e}"))?;
    let prompt_tokens = encoding.get_ids();
    let eos_token = loaded
        .tokenizer
        .token_to_id("</s>")
        .unwrap_or(2);

    let mut logits_processor = LogitsProcessor::from_sampling(
        42,
        Sampling::TopKThenTopP {
            k: 40,
            p: 0.9,
            temperature: 0.7,
        },
    );

    let mut all_tokens: Vec<u32> = prompt_tokens.to_vec();
    let mut input = Tensor::new(prompt_tokens, &loaded.device)
        .map_err(|e| format!("Tensor: {e}"))?
        .unsqueeze(0)
        .map_err(|e| format!("Unsqueeze: {e}"))?;

    for _ in 0..max_tokens {
        let logits = loaded
            .model
            .forward(&input, prompt_tokens.len())
            .map_err(|e| format!("Forward: {e}"))?;
        let logits = logits
            .squeeze(0)
            .map_err(|e| format!("Squeeze: {e}"))?;
        let next_token = logits_processor
            .sample(&logits)
            .map_err(|e| format!("Sample: {e}"))?;

        if next_token == eos_token {
            break;
        }

        all_tokens.push(next_token);
        input = Tensor::new(&[next_token], &loaded.device)
            .map_err(|e| format!("Tensor: {e}"))?
            .unsqueeze(0)
            .map_err(|e| format!("Unsqueeze: {e}"))?;
    }

    // Decode only the generated tokens (skip prompt)
    let generated = &all_tokens[prompt_tokens.len()..];
    loaded
        .tokenizer
        .decode(generated, true)
        .map_err(|e| format!("Decode: {e}"))
}

/// Build the tool-calling prompt that the orchestrator uses to decompose
/// a user query into PAP actions.
pub fn build_orchestrator_prompt(user_query: &str, available_tools: &[ToolDef]) -> String {
    let tools_json: Vec<String> = available_tools
        .iter()
        .map(|t| {
            format!(
                r#"  {{"tool": "{}", "description": "{}", "action": "{}"}}"#,
                t.name, t.description, t.action_type
            )
        })
        .collect();

    format!(
        r#"[INST] You are a PAP orchestrator. Given a user query, decompose it into one or more tool calls.

Available tools:
[
{tools}
]

Respond with a JSON array of tool calls. Each entry must have "tool" and "query" fields.
Example: [{{"tool": "web_search", "query": "best restaurants in Paris"}}]

User query: {query}
[/INST]"#,
        tools = tools_json.join(",\n"),
        query = user_query
    )
}

/// Definition of a tool available to the orchestrator.
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub action_type: String,
}

/// Model manager that owns the loaded model behind an Arc for sharing
/// across Tauri command handlers.
pub struct ModelManager {
    pub loaded: Option<LoadedModel>,
    pub model_id: String,
}

impl ModelManager {
    pub fn new() -> Self {
        Self {
            loaded: None,
            model_id: String::new(),
        }
    }

    /// Ensure the model is downloaded and loaded. No-op if already loaded
    /// with the same model_id.
    pub async fn ensure_loaded(&mut self, model_id: &str) -> Result<(), String> {
        if self.loaded.is_some() && self.model_id == model_id {
            return Ok(());
        }

        let info = resolve_model(model_id)
            .ok_or_else(|| format!("Unknown model: {model_id}"))?;

        let model_path = download_model(&info).await?;
        let tokenizer_path = download_tokenizer(&info).await?;

        let mut loaded = load_model(&model_path, &tokenizer_path)?;
        loaded.info = info;

        self.loaded = Some(loaded);
        self.model_id = model_id.to_string();
        Ok(())
    }

    /// Run inference. Returns an error if no model is loaded.
    pub fn generate(&mut self, prompt: &str, max_tokens: usize) -> Result<String, String> {
        let model = self
            .loaded
            .as_mut()
            .ok_or("No model loaded")?;
        generate(model, prompt, max_tokens)
    }
}
