//! On-device LLM inference via Candle.
//!
//! Models ship bundled inside the Tauri resource directory under `models/`.
//! Inference runs entirely offline — no HTTP calls, no data exfiltration.
//! This is the intended PAP architecture: the orchestrator decomposes
//! user queries into tool calls without ever touching the network.

use std::path::{Path, PathBuf};

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

/// Resolve the bundled GGUF weights file from the Tauri resource directory.
/// Expects `{resource_dir}/models/{filename}`.
pub fn resolve_bundled_model(
    resource_dir: &Path,
    info: &BuiltInModelInfo,
) -> Result<PathBuf, String> {
    let path = resource_dir.join("models").join(&info.filename);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "Bundled model not found: {} (expected at {})",
            info.filename,
            path.display()
        ))
    }
}

/// Resolve the bundled tokenizer from the Tauri resource directory.
/// Expects `{resource_dir}/models/tokenizer.json`.
pub fn resolve_bundled_tokenizer(resource_dir: &Path) -> Result<PathBuf, String> {
    let path = resource_dir.join("models").join("tokenizer.json");
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "Bundled tokenizer not found (expected at {})",
            path.display()
        ))
    }
}

/// Load a downloaded GGUF model into memory, ready for inference.
pub fn load_model(model_path: &Path, tokenizer_path: &Path) -> Result<LoadedModel, String> {
    let device = Device::Cpu;

    // Load GGUF
    let mut file = std::fs::File::open(model_path).map_err(|e| format!("Open model: {e}"))?;
    let gguf = gguf_file::Content::read(&mut file).map_err(|e| format!("Parse GGUF: {e}"))?;
    let weights = model::ModelWeights::from_gguf(gguf, &mut file, &device)
        .map_err(|e| format!("Load weights: {e}"))?;

    // Load tokenizer
    let tokenizer =
        Tokenizer::from_file(tokenizer_path).map_err(|e| format!("Load tokenizer: {e}"))?;

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
    let eos_token = loaded.tokenizer.token_to_id("</s>").unwrap_or(2);

    let mut logits_processor = LogitsProcessor::from_sampling(
        42,
        Sampling::TopKThenTopP {
            k: 40,
            p: 0.9,
            temperature: 0.7,
        },
    );

    let prompt_len = prompt_tokens.len();
    let mut all_tokens: Vec<u32> = prompt_tokens.to_vec();
    let mut input = Tensor::new(prompt_tokens, &loaded.device)
        .map_err(|e| format!("Tensor: {e}"))?
        .unsqueeze(0)
        .map_err(|e| format!("Unsqueeze: {e}"))?;

    // Position tracking for rotary embeddings and KV cache:
    // - First pass processes the full prompt starting at position 0
    // - Subsequent passes process one token at a time, incrementing position
    let mut pos = 0usize;

    for _ in 0..max_tokens {
        let logits = loaded
            .model
            .forward(&input, pos)
            .map_err(|e| format!("Forward: {e}"))?;
        let logits = logits.squeeze(0).map_err(|e| format!("Squeeze: {e}"))?;
        let next_token = logits_processor
            .sample(&logits)
            .map_err(|e| format!("Sample: {e}"))?;

        if next_token == eos_token {
            break;
        }

        all_tokens.push(next_token);

        // After processing the full prompt, jump to prompt_len;
        // after each subsequent single token, increment by 1.
        if pos == 0 {
            pos = prompt_len;
        } else {
            pos += 1;
        }

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
#[derive(Default)]
pub struct ModelManager {
    pub loaded: Option<LoadedModel>,
    pub model_id: String,
}

impl ModelManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the bundled model from the resource directory.
    /// No-op if already loaded with the same model_id.
    pub fn ensure_loaded(&mut self, model_id: &str, resource_dir: &Path) -> Result<(), String> {
        if self.loaded.is_some() && self.model_id == model_id {
            return Ok(());
        }

        let info = resolve_model(model_id).ok_or_else(|| format!("Unknown model: {model_id}"))?;

        let model_path = resolve_bundled_model(resource_dir, &info)?;
        let tokenizer_path = resolve_bundled_tokenizer(resource_dir)?;

        let mut loaded = load_model(&model_path, &tokenizer_path)?;
        loaded.info = info;

        self.loaded = Some(loaded);
        self.model_id = model_id.to_string();
        Ok(())
    }

    /// Run inference. Returns an error if no model is loaded.
    pub fn generate(&mut self, prompt: &str, max_tokens: usize) -> Result<String, String> {
        let model = self.loaded.as_mut().ok_or("No model loaded")?;
        generate(model, prompt, max_tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── resolve_model ───────────────────────────────────────

    #[test]
    fn resolve_known_model() {
        let info = resolve_model("tinyllama-1.1b").expect("should resolve");
        assert_eq!(info.id, "tinyllama-1.1b");
        assert!(info.filename.ends_with(".gguf"));
        assert!(info.repo.contains("TinyLlama"));
    }

    #[test]
    fn resolve_all_catalog_models() {
        for entry in builtin_model_catalog() {
            let resolved = resolve_model(&entry.id);
            assert!(resolved.is_some(), "failed to resolve {}", entry.id);
            assert_eq!(resolved.unwrap().id, entry.id);
        }
    }

    #[test]
    fn resolve_unknown_model_returns_none() {
        assert!(resolve_model("nonexistent-model-xyz").is_none());
    }

    #[test]
    fn resolve_empty_string_returns_none() {
        assert!(resolve_model("").is_none());
    }

    // ── build_orchestrator_prompt ────────────────────────────

    #[test]
    fn prompt_contains_user_query() {
        let prompt = build_orchestrator_prompt("find cheap flights to Paris", &[]);
        assert!(prompt.contains("find cheap flights to Paris"));
    }

    #[test]
    fn prompt_uses_inst_tags() {
        let prompt = build_orchestrator_prompt("test", &[]);
        assert!(prompt.starts_with("[INST]"));
        assert!(prompt.ends_with("[/INST]"));
    }

    #[test]
    fn prompt_includes_tool_definitions() {
        let tools = vec![
            ToolDef {
                name: "web_search".into(),
                description: "Search the web".into(),
                action_type: "schema:SearchAction".into(),
            },
            ToolDef {
                name: "book_flight".into(),
                description: "Book a flight".into(),
                action_type: "schema:ReserveAction".into(),
            },
        ];
        let prompt = build_orchestrator_prompt("fly to tokyo", &tools);
        assert!(prompt.contains("web_search"));
        assert!(prompt.contains("book_flight"));
        assert!(prompt.contains("schema:SearchAction"));
        assert!(prompt.contains("schema:ReserveAction"));
    }

    #[test]
    fn prompt_with_no_tools_still_valid() {
        let prompt = build_orchestrator_prompt("hello", &[]);
        assert!(prompt.contains("[INST]"));
        assert!(prompt.contains("hello"));
        assert!(prompt.contains("Available tools:"));
    }

    #[test]
    fn prompt_contains_json_example() {
        let prompt = build_orchestrator_prompt("test", &[]);
        assert!(prompt.contains(r#""tool""#));
        assert!(prompt.contains(r#""query""#));
    }

    // ── ModelManager ────────────────────────────────────────

    #[test]
    fn model_manager_starts_unloaded() {
        let mgr = ModelManager::new();
        assert!(mgr.loaded.is_none());
        assert!(mgr.model_id.is_empty());
    }

    #[test]
    fn model_manager_generate_fails_without_model() {
        let mut mgr = ModelManager::new();
        let result = mgr.generate("hello", 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("No model loaded"));
    }

    // ── load_model error paths ──────────────────────────────

    #[test]
    fn load_model_fails_on_missing_file() {
        let bad_model = PathBuf::from("/nonexistent/model.gguf");
        let bad_tokenizer = PathBuf::from("/nonexistent/tokenizer.json");
        let result = load_model(&bad_model, &bad_tokenizer);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("Open model"), "unexpected error: {err}");
    }

    // ── ToolDef ─────────────────────────────────────────────

    #[test]
    fn tool_def_fields_accessible() {
        let tool = ToolDef {
            name: "test".into(),
            description: "a test tool".into(),
            action_type: "schema:TestAction".into(),
        };
        assert_eq!(tool.name, "test");
        assert_eq!(tool.description, "a test tool");
        assert_eq!(tool.action_type, "schema:TestAction");
    }
}
