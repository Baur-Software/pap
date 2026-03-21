use std::sync::Arc;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde_json::json;

use crate::inference::ModelManager;

use super::session_store::SessionStore;

/// On-device AI agent.
///
/// Runs inference via Candle on the local TinyLlama model — zero disclosure,
/// prompts never leave the device. The prompt arrives via `handle_disclosure`.
/// Sessions are TTL-bounded and reaped automatically.
pub struct OnDeviceAiAgent {
    model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
    sessions: SessionStore<Option<String>>, // prompt
}

impl OnDeviceAiAgent {
    pub fn new(model_manager: Arc<tokio::sync::Mutex<ModelManager>>) -> Self {
        Self {
            model_manager,
            sessions: SessionStore::new(),
        }
    }
}

impl AgentHandler for OnDeviceAiAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:AskAction" {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}", token.action
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let did = self.sessions.insert(session_id.clone(), None);
        Ok((session_id, did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        if !self.sessions.exists(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        let prompt = disclosures
            .iter()
            .find_map(|d| d.get("query").and_then(|v| v.as_str()))
            .map(String::from);

        if let Some(p) = prompt {
            self.sessions.with_mut(session_id, |data| {
                *data = Some(p);
            })?;
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let prompt = self.sessions.with(session_id, |data| data.clone())?
            .ok_or_else(|| TransportError::ServerError("No prompt provided in disclosures".into()))?;

        let mut mgr = self.model_manager.try_lock().map_err(|_| {
            TransportError::ServerError("Model manager busy".into())
        })?;

        if mgr.loaded.is_none() {
            return Err(TransportError::ServerError(
                "No model loaded. Configure a BuiltIn provider in Settings.".into(),
            ));
        }

        let llm_prompt = format!("[INST] {} [/INST]", prompt);
        let response = mgr
            .generate(&llm_prompt, 300)
            .map_err(|e| TransportError::ServerError(format!("Inference failed: {e}")))?;

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "Answer",
            "text": response
        }))
    }

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        let key = self.sessions.signing_key(
            &receipt.session_id,
        );
        match key {
            Some(k) => receipt.co_sign(&k),
            None => {
                let k = SessionKeypair::generate();
                receipt.co_sign(k.signing_key());
            }
        }
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}
