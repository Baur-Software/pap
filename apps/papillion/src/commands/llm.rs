use papillion_shared::LlmProvider;
use serde::{Deserialize, Serialize};

use crate::error::PapillionError;

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

/// Send a chat completion request to the configured LLM provider.
/// Returns the assistant's response content.
///
/// For BuiltIn, use `crate::inference::ModelManager` directly — this
/// function only handles the HTTP-based providers.
pub async fn chat(provider: &LlmProvider, messages: &[ChatMessage]) -> Result<String, PapillionError> {
    match provider {
        LlmProvider::BuiltIn { .. } => {
            Err(PapillionError::from(
                "BuiltIn provider uses on-device inference via ModelManager, not HTTP chat",
            ))
        }
        LlmProvider::Ollama { endpoint, model } => ollama_chat(endpoint, model, messages).await,
        LlmProvider::OpenAiCompatible { endpoint, api_key, model } => {
            openai_chat(endpoint, api_key, model, messages).await
        }
        LlmProvider::None => Err(PapillionError::from("No LLM provider configured")),
    }
}

/// Check if the configured LLM provider is reachable.
#[tauri::command]
pub async fn check_llm_connection(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<String, PapillionError> {
    let config = state
        .orchestrator_config
        .read()
        .map_err(|e| PapillionError::from(e.to_string()))?
        .clone();

    let messages = vec![ChatMessage {
        role: "user".into(),
        content: "Say hello in one sentence.".into(),
    }];

    let response = chat(&config.llm_provider, &messages).await?;
    Ok(response)
}

// ── Ollama ───────────────────────────────────────────────────

async fn ollama_chat(
    endpoint: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, PapillionError> {
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
        .map_err(|e| PapillionError::from(format!("Ollama request failed: {e}")))?
        .json()
        .await
        .map_err(|e| PapillionError::from(format!("Ollama response parse failed: {e}")))?;

    Ok(resp.message.content)
}

// ── OpenAI-compatible ────────────────────────────────────────

async fn openai_chat(
    endpoint: &str,
    api_key: &str,
    model: &str,
    messages: &[ChatMessage],
) -> Result<String, PapillionError> {
    let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
    let body = OpenAiRequest { model, messages };

    let client = reqwest::Client::new();
    let resp: OpenAiResponse = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&body)
        .send()
        .await
        .map_err(|e| PapillionError::from(format!("OpenAI request failed: {e}")))?
        .json()
        .await
        .map_err(|e| PapillionError::from(format!("OpenAI response parse failed: {e}")))?;

    resp.choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| PapillionError::from("No response from model"))
}
