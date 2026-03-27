use std::sync::Arc;

use pap_agents::{AgentExecutor, AgentMeta};
use pap_transport::TransportError;
use serde_json::json;

use crate::inference::ModelManager;

/// On-device AI agent — runs Candle/TinyLlama locally.
///
/// Zero disclosure, prompts never leave the device.
/// Lives in Papillon (not pap-agents) because it depends on ModelManager.
pub struct OnDeviceAiExecutor {
    model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
}

impl OnDeviceAiExecutor {
    pub fn new(model_manager: Arc<tokio::sync::Mutex<ModelManager>>) -> Self {
        Self { model_manager }
    }
}

impl AgentExecutor for OnDeviceAiExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "On-Device AI",
            provider: "Papillon",
            action: "schema:AskAction",
            object_types: &["schema:Question"],
            requires_disclosure: &[],
            returns: &["schema:Answer"],
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

        let llm_prompt = format!("[INST] {} [/INST]", query);
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
