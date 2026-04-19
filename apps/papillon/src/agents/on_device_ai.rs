use std::sync::Arc;

use pap_agents::{AgentExecutor, AgentMeta};
use pap_transport::TransportError;
use serde_json::json;
use tokio::sync::watch;

use crate::inference::ModelManager;

/// On-device AI agent — runs Candle/TinyLlama locally.
///
/// Zero disclosure, prompts never leave the device.
/// Lives in Papillon (not pap-agents) because it depends on ModelManager.
///
/// Receives a `watch::Receiver<String>` for the personal-context preamble.
/// The preamble (built from EpisodeDB + user traits) is prepended to every
/// prompt so the on-device model acts as a memex-backed personal agent rather
/// than a stateless assistant.
pub struct OnDeviceAiExecutor {
    model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
    /// Personal context preamble channel.  Borrow the latest value at call time.
    context_rx: watch::Receiver<String>,
}

impl OnDeviceAiExecutor {
    pub fn new(
        model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
        context_rx: watch::Receiver<String>,
    ) -> Self {
        Self {
            model_manager,
            context_rx,
        }
    }
}

impl AgentExecutor for OnDeviceAiExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "On-Device AI",
            version: "0.1.0",
            provider: "Papillon",
            action: "schema:AskAction",
            object_types: &["schema:Question"],
            requires_disclosure: &[],
            returns: &["schema:Answer"],
            configurable_properties: vec![],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let mut mgr = self
            .model_manager
            .try_lock()
            .map_err(|_| TransportError::ServerError("Model manager busy".into()))?;

        if mgr.loaded.is_none() {
            return Err(TransportError::ServerError(
                "No model loaded. Configure a BuiltIn provider in Settings.".into(),
            ));
        }

        // Borrow the latest personal context preamble.  The watch channel
        // always holds the most-recent value; no polling or blocking required.
        let preamble = self.context_rx.borrow().clone();
        let llm_prompt = if preamble.is_empty() {
            format!("[INST] {query} [/INST]")
        } else {
            format!("[INST] {preamble}\n\n{query} [/INST]")
        };

        let response = mgr
            .generate(&llm_prompt, 300)
            .map_err(|e| TransportError::ServerError(format!("Inference failed: {e}")))?;

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "Answer",
            "text": response
        }))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the context preamble is injected before the query in the LLM prompt.
    ///
    /// We cannot call `execute()` without a loaded model, so this test exercises
    /// the prompt-building logic directly by inspecting `llm_prompt` construction.
    /// We validate the ordering contract: preamble appears before user query.
    #[test]
    fn context_prepended_when_nonempty() {
        let (tx, rx) = watch::channel(
            "[PAP PERSONAL CONTEXT]\n{\"recentEpisodes\":[]}\n[END PAP CONTEXT]".to_string(),
        );

        // Build the prompt the same way execute() does so we can assert ordering.
        let preamble = rx.borrow().clone();
        let query = "What is Rust?";
        let prompt = if preamble.is_empty() {
            format!("[INST] {query} [/INST]")
        } else {
            format!("[INST] {preamble}\n\n{query} [/INST]")
        };

        // Preamble must appear before the query.
        let preamble_pos = prompt
            .find("[PAP PERSONAL CONTEXT]")
            .expect("preamble present");
        let query_pos = prompt.find(query).expect("query present");
        assert!(
            preamble_pos < query_pos,
            "preamble must precede query in prompt"
        );

        // Updating the channel reflects on the next borrow.
        tx.send("new context".to_string()).unwrap();
        let updated = rx.borrow().clone();
        assert_eq!(updated, "new context");
    }

    #[test]
    fn empty_context_omits_preamble() {
        let (_tx, rx) = watch::channel(String::new());
        let preamble = rx.borrow().clone();
        let query = "Hello";
        let prompt = if preamble.is_empty() {
            format!("[INST] {query} [/INST]")
        } else {
            format!("[INST] {preamble}\n\n{query} [/INST]")
        };
        assert_eq!(prompt, "[INST] Hello [/INST]");
    }
}
