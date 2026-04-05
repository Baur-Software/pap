//! `SimpleAgent<E>` — generic wrapper that turns an `AgentExecutor` into
//! a full `AgentHandler` with standard session management, disclosure
//! extraction, and receipt co-signing.
//!
//! All 5 boilerplate phases are implemented once here. Individual agents
//! only provide `meta()` + `execute(query)`.

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};

use crate::executor::AgentExecutor;
use crate::session_store::SessionStore;

/// Wraps an `AgentExecutor` into a full `AgentHandler`.
pub struct SimpleAgent<E> {
    executor: E,
    sessions: SessionStore<Option<String>>,
}

impl<E: AgentExecutor> SimpleAgent<E> {
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            sessions: SessionStore::new(),
        }
    }

    /// Access the underlying executor (for reading metadata, etc.).
    pub fn executor(&self) -> &E {
        &self.executor
    }
}

impl<E: AgentExecutor> AgentHandler for SimpleAgent<E> {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        let expected = self.executor.meta().action;
        if token.action != expected {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}",
                token.action
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
        let query = disclosures
            .iter()
            .find_map(|d| d.get("query").and_then(|v| v.as_str()))
            .map(String::from);

        if let Some(q) = query {
            self.sessions.with_mut(session_id, |data| {
                *data = Some(q);
            })?;
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let query = self
            .sessions
            .with(session_id, |data| data.clone())?
            .ok_or_else(|| {
                TransportError::ServerError("No query provided in disclosures".into())
            })?;
        self.executor.execute(&query)
    }

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        let key = self.sessions.signing_key(&receipt.session_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::AgentMeta;
    use serde_json::json;

    struct EchoExecutor;

    impl AgentExecutor for EchoExecutor {
        fn meta(&self) -> AgentMeta {
            AgentMeta {
                name: "Echo",
                provider: "Test",
                action: "schema:SearchAction",
                object_types: &["schema:Thing"],
                requires_disclosure: &[],
                returns: &["schema:Thing"],
            }
        }

        fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
            Ok(json!({
                "@context": "https://schema.org",
                "@type": "Thing",
                "name": query
            }))
        }
    }

    fn make_token(action: &str) -> CapabilityToken {
        let kp = pap_did::PrincipalKeypair::generate();
        let mut token = CapabilityToken::mint(
            "did:key:test".into(),
            action.into(),
            kp.did(),
            chrono::Utc::now() + chrono::Duration::hours(1),
        );
        token.sign(kp.signing_key()).unwrap();
        token
    }

    #[test]
    fn rejects_wrong_action() {
        let agent = SimpleAgent::new(EchoExecutor);
        assert!(agent.handle_token(make_token("schema:Wrong")).is_err());
    }

    #[test]
    fn accepts_correct_action() {
        let agent = SimpleAgent::new(EchoExecutor);
        assert!(agent
            .handle_token(make_token("schema:SearchAction"))
            .is_ok());
    }

    #[test]
    fn full_session_lifecycle() {
        let agent = SimpleAgent::new(EchoExecutor);
        let (sid, _) = agent
            .handle_token(make_token("schema:SearchAction"))
            .unwrap();
        agent.handle_did_exchange(&sid, "did:key:peer").unwrap();
        agent
            .handle_disclosure(&sid, vec![json!({"query": "hello"})])
            .unwrap();
        let result = agent.execute(&sid).unwrap();
        assert_eq!(result["name"], "hello");
        agent.handle_close(&sid).unwrap();
    }

    #[test]
    fn unknown_session_errors() {
        let agent = SimpleAgent::new(EchoExecutor);
        assert!(agent.handle_did_exchange("nope", "did:key:x").is_err());
    }
}
