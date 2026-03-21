use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde_json::json;

use crate::inference::ModelManager;

struct SessionState {
    session_key: SessionKeypair,
    prompt: Option<String>,
}

/// On-device AI agent.
///
/// Runs inference via Candle on the local TinyLlama model — zero disclosure,
/// prompts never leave the device. The prompt arrives via `handle_disclosure`.
pub struct OnDeviceAiAgent {
    model_manager: Arc<tokio::sync::Mutex<ModelManager>>,
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl OnDeviceAiAgent {
    pub fn new(model_manager: Arc<tokio::sync::Mutex<ModelManager>>) -> Self {
        Self {
            model_manager,
            sessions: Mutex::new(HashMap::new()),
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
        let session_key = SessionKeypair::generate();
        let receiver_did = session_key.did();

        self.sessions.lock().unwrap().insert(
            session_id.clone(),
            SessionState { session_key, prompt: None },
        );

        Ok((session_id, receiver_did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        if !self.sessions.lock().unwrap().contains_key(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| TransportError::ServerError("Unknown session".into()))?;

        for d in &disclosures {
            if let Some(q) = d.get("query").and_then(|v| v.as_str()) {
                session.prompt = Some(q.to_string());
            }
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let prompt = {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get(session_id)
                .ok_or_else(|| TransportError::ServerError("Unknown session".into()))?;
            session.prompt.clone()
                .ok_or_else(|| TransportError::ServerError("No prompt provided in disclosures".into()))?
        };

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
        let sessions = self.sessions.lock().unwrap();
        let key = sessions
            .values()
            .next()
            .map(|s| s.session_key.signing_key().clone());
        drop(sessions);

        if let Some(k) = key {
            receipt.co_sign(&k);
        } else {
            let k = SessionKeypair::generate();
            receipt.co_sign(k.signing_key());
        }
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }
}
