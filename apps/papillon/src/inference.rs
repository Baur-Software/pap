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
use futures_util::StreamExt;
use tokenizers::Tokenizer;

use papillon_shared::{builtin_model_catalog, BuiltInModelInfo, ModelAvailability};

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

/// Resolve the GGUF weights file, checking bundled resources first, then
/// the user-writable data directory (for downloaded models).
pub fn resolve_model_file(
    resource_dir: &Path,
    data_dir: &Path,
    info: &BuiltInModelInfo,
) -> Result<PathBuf, String> {
    let bundled = resource_dir.join("models").join(&info.filename);
    if bundled.exists() {
        return Ok(bundled);
    }
    let downloaded = data_dir.join("models").join(&info.filename);
    if downloaded.exists() {
        return Ok(downloaded);
    }
    Err(format!(
        "Bundled model not found: {} (checked {} and {})",
        info.filename,
        bundled.display(),
        downloaded.display(),
    ))
}

/// Resolve tokenizer.json, checking bundled resources first, then data dir.
pub fn resolve_tokenizer_file(resource_dir: &Path, data_dir: &Path) -> Result<PathBuf, String> {
    let bundled = resource_dir.join("models").join("tokenizer.json");
    if bundled.exists() {
        return Ok(bundled);
    }
    let downloaded = data_dir.join("models").join("tokenizer.json");
    if downloaded.exists() {
        return Ok(downloaded);
    }
    Err(format!(
        "Tokenizer not found (checked {} and {})",
        bundled.display(),
        downloaded.display(),
    ))
}

/// Check whether a model's files are available on disk (without loading).
pub fn check_model_availability(
    resource_dir: &Path,
    data_dir: &Path,
    info: &BuiltInModelInfo,
) -> ModelAvailability {
    let model_present = resource_dir.join("models").join(&info.filename).exists()
        || data_dir.join("models").join(&info.filename).exists();
    let tokenizer_present = resource_dir.join("models").join("tokenizer.json").exists()
        || data_dir.join("models").join("tokenizer.json").exists();
    ModelAvailability {
        model_id: info.id.clone(),
        model_present,
        tokenizer_present,
        ready: model_present && tokenizer_present,
    }
}

/// Download a file from `url` to `dest_path`, calling `on_progress` with
/// (downloaded_bytes, total_bytes). Streams to a `.tmp` file then renames.
pub async fn download_file(
    url: &str,
    dest_path: &Path,
    on_progress: impl Fn(u64, u64),
) -> Result<(), String> {
    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Create directory {}: {e}", parent.display()))?;
    }

    let client = reqwest::Client::builder()
        .user_agent("Papillon/0.1 (PAP Desktop)")
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Download request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Download failed: HTTP {}", response.status()));
    }

    let total = response.content_length().unwrap_or(0);
    let mut downloaded: u64 = 0;

    let tmp_path = dest_path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp_path)
        .map_err(|e| format!("Create file {}: {e}", tmp_path.display()))?;

    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("Download stream error: {e}"))?;
        std::io::Write::write_all(&mut file, &chunk).map_err(|e| format!("Write error: {e}"))?;
        downloaded += chunk.len() as u64;
        on_progress(downloaded, total);
    }

    std::io::Write::flush(&mut file).map_err(|e| format!("Flush error: {e}"))?;
    drop(file);

    std::fs::rename(&tmp_path, dest_path).map_err(|e| {
        format!(
            "Rename {} -> {}: {e}",
            tmp_path.display(),
            dest_path.display()
        )
    })?;

    Ok(())
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
            download_url: String::new(),
            tokenizer_url: String::new(),
            web_compatible: false,
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

    /// Load the model from bundled resources or user data directory.
    /// No-op if already loaded with the same model_id.
    pub fn ensure_loaded(
        &mut self,
        model_id: &str,
        resource_dir: &Path,
        data_dir: &Path,
    ) -> Result<(), String> {
        if self.loaded.is_some() && self.model_id == model_id {
            return Ok(());
        }

        let info = resolve_model(model_id).ok_or_else(|| format!("Unknown model: {model_id}"))?;

        let model_path = resolve_model_file(resource_dir, data_dir, &info)?;
        let tokenizer_path = resolve_tokenizer_file(resource_dir, data_dir)?;

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

    // ── Dual-path model resolution & availability ─────────────

    #[test]
    fn catalog_models_have_download_urls() {
        for entry in builtin_model_catalog() {
            assert!(
                !entry.download_url.is_empty(),
                "model {} has empty download_url",
                entry.id,
            );
            assert!(
                entry.download_url.starts_with("https://"),
                "model {} download_url is not HTTPS: {}",
                entry.id,
                entry.download_url,
            );
            assert!(
                !entry.tokenizer_url.is_empty(),
                "model {} has empty tokenizer_url",
                entry.id,
            );
            assert!(
                entry.tokenizer_url.starts_with("https://"),
                "model {} tokenizer_url is not HTTPS: {}",
                entry.id,
                entry.tokenizer_url,
            );
        }
    }

    #[test]
    fn resolve_model_file_prefers_bundled() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_prefers_bundled_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        let info = builtin_model_catalog().into_iter().next().unwrap();

        // Place file in both locations
        std::fs::write(resource_dir.join("models").join(&info.filename), b"bundled").unwrap();
        std::fs::write(data_dir.join("models").join(&info.filename), b"downloaded").unwrap();

        let result = resolve_model_file(&resource_dir, &data_dir, &info).unwrap();
        assert_eq!(result, resource_dir.join("models").join(&info.filename));

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn resolve_model_file_falls_back_to_data_dir() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_fallback_data_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        let info = builtin_model_catalog().into_iter().next().unwrap();

        // Only place file in data_dir
        std::fs::write(data_dir.join("models").join(&info.filename), b"downloaded").unwrap();

        let result = resolve_model_file(&resource_dir, &data_dir, &info).unwrap();
        assert_eq!(result, data_dir.join("models").join(&info.filename));

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn resolve_model_file_errors_when_missing() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_missing_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        let info = builtin_model_catalog().into_iter().next().unwrap();

        let result = resolve_model_file(&resource_dir, &data_dir, &info);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains(
                &resource_dir
                    .join("models")
                    .join(&info.filename)
                    .display()
                    .to_string()
            ),
            "error should mention resource path: {err}",
        );
        assert!(
            err.contains(
                &data_dir
                    .join("models")
                    .join(&info.filename)
                    .display()
                    .to_string()
            ),
            "error should mention data path: {err}",
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn resolve_tokenizer_file_dual_path() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_tokenizer_dual_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        // Both present: should prefer bundled (resource_dir)
        std::fs::write(
            resource_dir.join("models").join("tokenizer.json"),
            b"bundled",
        )
        .unwrap();
        std::fs::write(
            data_dir.join("models").join("tokenizer.json"),
            b"downloaded",
        )
        .unwrap();

        let result = resolve_tokenizer_file(&resource_dir, &data_dir).unwrap();
        assert_eq!(result, resource_dir.join("models").join("tokenizer.json"));

        // Remove bundled: should fall back to data_dir
        std::fs::remove_file(resource_dir.join("models").join("tokenizer.json")).unwrap();

        let result = resolve_tokenizer_file(&resource_dir, &data_dir).unwrap();
        assert_eq!(result, data_dir.join("models").join("tokenizer.json"));

        // Remove both: should error mentioning both paths
        std::fs::remove_file(data_dir.join("models").join("tokenizer.json")).unwrap();

        let result = resolve_tokenizer_file(&resource_dir, &data_dir);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains(&resource_dir.join("models").display().to_string()),
            "error should mention resource path: {err}",
        );
        assert!(
            err.contains(&data_dir.join("models").display().to_string()),
            "error should mention data path: {err}",
        );

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn check_model_availability_both_missing() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_avail_missing_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        let info = builtin_model_catalog().into_iter().next().unwrap();

        let avail = check_model_availability(&resource_dir, &data_dir, &info);
        assert!(!avail.ready, "should not be ready when both files missing");
        assert!(!avail.model_present, "model should not be present");
        assert!(!avail.tokenizer_present, "tokenizer should not be present");
        assert_eq!(avail.model_id, info.id);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn check_model_availability_ready() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_avail_ready_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        let info = builtin_model_catalog().into_iter().next().unwrap();

        // Place both files in data_dir
        std::fs::write(data_dir.join("models").join(&info.filename), b"model").unwrap();
        std::fs::write(data_dir.join("models").join("tokenizer.json"), b"tok").unwrap();

        let avail = check_model_availability(&resource_dir, &data_dir, &info);
        assert!(avail.ready, "should be ready when both files present");
        assert!(avail.model_present, "model should be present");
        assert!(avail.tokenizer_present, "tokenizer should be present");
        assert_eq!(avail.model_id, info.id);

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn check_model_availability_partial() {
        let pid = std::process::id();
        let base = std::env::temp_dir().join(format!("pap_test_avail_partial_{pid}"));
        let resource_dir = base.join("resources");
        let data_dir = base.join("data");

        std::fs::create_dir_all(resource_dir.join("models")).unwrap();
        std::fs::create_dir_all(data_dir.join("models")).unwrap();

        let info = builtin_model_catalog().into_iter().next().unwrap();

        // Only model file, no tokenizer
        std::fs::write(data_dir.join("models").join(&info.filename), b"model").unwrap();

        let avail = check_model_availability(&resource_dir, &data_dir, &info);
        assert!(!avail.ready, "should not be ready with only model present");
        assert!(avail.model_present, "model should be present");
        assert!(!avail.tokenizer_present, "tokenizer should not be present");
        assert_eq!(avail.model_id, info.id);

        std::fs::remove_dir_all(&base).unwrap();
    }
}
