use papillon_shared::LlmProvider;
use serde::{Deserialize, Serialize};

use crate::error::PapillonError;

// ── Request / response types ─────────────────────────────────

#[derive(Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    stream: bool,
}

#[derive(Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Deserialize)]
struct OllamaMessage {
    content: String,
}

#[derive(Serialize)]
struct OpenAiRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
}

/// HuggingFace Inference API (text-generation task, Chat Completions format).
#[derive(Serialize)]
struct HfRequest<'a> {
    inputs: &'a str,
    parameters: HfParameters,
}

#[derive(Serialize)]
struct HfParameters {
    max_new_tokens: u32,
    return_full_text: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HfResponse {
    List(Vec<HfGenerated>),
    Error { error: String },
}

#[derive(Deserialize)]
struct HfGenerated {
    generated_text: String,
}

#[derive(Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMsg,
}

#[derive(Deserialize)]
struct OpenAiMsg {
    content: String,
}

#[derive(Clone, Serialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

// ── Public API ───────────────────────────────────────────────

/// Send a chat completion request to an HTTP-based LLM provider.
/// Returns the assistant's response content.
///
/// For BuiltIn, callers should use `crate::inference::ModelManager` directly.
/// This function handles Mistral API, Ollama, and OpenAI-compatible endpoints.
pub async fn chat(
    provider: &LlmProvider,
    messages: &[ChatMessage],
) -> Result<String, PapillonError> {
    match provider {
        LlmProvider::BuiltIn { .. } => Err(PapillonError::from(
            "BuiltIn provider uses on-device inference via ModelManager, not HTTP chat",
        )),
        LlmProvider::Mistral { api_key, model } => mistral_chat(api_key, model, messages).await,
        LlmProvider::Ollama { endpoint, model } => ollama_chat(endpoint, model, messages).await,
        LlmProvider::OpenAiCompatible {
            endpoint,
            api_key,
            model,
        } => openai_chat(endpoint, api_key, model, messages).await,
        LlmProvider::HuggingFace { api_token, model } => hf_chat(api_token, model, messages).await,
        LlmProvider::None => Err(PapillonError::from("No LLM provider configured")),
    }
}

/// Check if the configured LLM provider is reachable and working.
#[tauri::command]
pub async fn check_llm_connection(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<String, PapillonError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillonError::from(e.to_string()))?
        .clone();

    match &config.inference_substrate {
        LlmProvider::BuiltIn { model_id } => {
            // For BuiltIn, verify the model is loaded and can generate
            let resource_dir = state
                .resource_dir
                .read()
                .map_err(|e| PapillonError::from(e.to_string()))?
                .clone();
            let data_dir = state
                .data_dir
                .read()
                .map_err(|e| PapillonError::from(e.to_string()))?
                .clone();
            let mut mgr = state.model_manager.lock().await;
            mgr.ensure_loaded(model_id, &resource_dir, &data_dir)
                .map_err(PapillonError::from)?;
            // Pick the right prompt format for the loaded architecture
            let probe = crate::inference::build_orchestrator_prompt_with_template(
                "Say hello in one sentence.",
                &[],
                mgr.loaded
                    .as_ref()
                    .map(|m| crate::inference::ChatTemplate::from_backend(&m.model))
                    .unwrap_or(crate::inference::ChatTemplate::Llama),
            );
            let response = mgr.generate(&probe, 50).map_err(PapillonError::from)?;
            Ok(response)
        }
        LlmProvider::None => Err(PapillonError::from("No LLM provider configured")),
        other => {
            let messages = vec![ChatMessage {
                role: "user".into(),
                content: "Say hello in one sentence.".into(),
            }];
            chat(other, &messages).await
        }
    }
}

// ── Ollama ───────────────────────────────────────────────────

async fn ollama_chat(
    endpoint: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, PapillonError> {
    let url = format!("{}/api/chat", endpoint.trim_end_matches('/'));
    let body = OllamaRequest {
        model,
        messages,
        stream: false,
    };

    let client = reqwest::Client::new();
    let resp: OllamaResponse = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| PapillonError::from(format!("Ollama request failed: {e}")))?
        .json()
        .await
        .map_err(|e| PapillonError::from(format!("Ollama response parse failed: {e}")))?;

    Ok(resp.message.content)
}

// ── Mistral API ─────────────────────────────────────────────

const MISTRAL_API_ENDPOINT: &str = "https://api.mistral.ai/v1";

async fn mistral_chat(
    api_key: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, PapillonError> {
    openai_chat(MISTRAL_API_ENDPOINT, api_key, model, messages).await
}

// ── OpenAI-compatible ────────────────────────────────────────

async fn openai_chat(
    endpoint: &str,
    api_key: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, PapillonError> {
    let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
    let body = OpenAiRequest { model, messages };

    let client = reqwest::Client::new();
    let resp: OpenAiResponse = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| PapillonError::from(format!("OpenAI request failed: {e}")))?
        .json()
        .await
        .map_err(|e| PapillonError::from(format!("OpenAI response parse failed: {e}")))?;

    resp.choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| PapillonError::from("No response from model"))
}

// ── HuggingFace Inference API ─────────────────────────────────

const HF_INFERENCE_BASE: &str = "https://api-inference.huggingface.co/models";

async fn hf_chat(
    api_token: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, PapillonError> {
    // Flatten messages into a single prompt string — the HF text-generation
    // API does not support the chat-completions format for all models.
    let prompt = messages
        .iter()
        .map(|m| format!("{}: {}", m.role, m.content))
        .collect::<Vec<_>>()
        .join("\n");

    let url = format!("{HF_INFERENCE_BASE}/{model}");
    let body = HfRequest {
        inputs: &prompt,
        parameters: HfParameters {
            max_new_tokens: 512,
            return_full_text: false,
        },
    };

    let client = reqwest::Client::new();
    let raw = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| PapillonError::from(format!("HuggingFace request failed: {e}")))?
        .json::<HfResponse>()
        .await
        .map_err(|e| PapillonError::from(format!("HuggingFace response parse failed: {e}")))?;

    match raw {
        HfResponse::List(mut items) => items
            .pop()
            .map(|r| r.generated_text)
            .ok_or_else(|| PapillonError::from("HuggingFace returned empty response")),
        HfResponse::Error { error } => Err(PapillonError::from(format!(
            "HuggingFace API error: {error}"
        ))),
    }
}
