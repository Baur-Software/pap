//! Remote agent handler — bridges the sync `AgentHandler` trait
//! to an async `AgentClient` over TLS.
//!
//! This allows the orchestrator's handshake module to treat remote
//! agents identically to local ones — same trait, same code path.

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;

use crate::client::AgentClient;
use crate::error::TransportError;
use crate::handler::AgentHandler;

/// An `AgentHandler` that delegates to a remote agent over HTTPS.
///
/// Uses `tokio::task::block_in_place` to run async HTTP calls from
/// within the sync `AgentHandler` trait methods.
///
/// Tracks the session_id from phase 1 (handle_token) so that phase 5
/// (co_sign_receipt) can route the receipt to the correct session
/// on the remote node.
pub struct RemoteAgentHandler {
    client: AgentClient,
    /// Session ID returned by the remote agent in phase 1.
    /// Stored here because co_sign_receipt doesn't receive it as a parameter.
    last_session_id: std::sync::Mutex<Option<String>>,
}

impl RemoteAgentHandler {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: AgentClient::new(base_url),
            last_session_id: std::sync::Mutex::new(None),
        }
    }

    pub fn with_client(base_url: &str, http_client: reqwest::Client) -> Self {
        Self {
            client: AgentClient::with_client(base_url, http_client),
            last_session_id: std::sync::Mutex::new(None),
        }
    }

    /// Block on an async future from a sync context.
    fn block_on<F: std::future::Future<Output = T>, T>(f: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    }
}

impl AgentHandler for RemoteAgentHandler {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        let resp = Self::block_on(self.client.present_token(token))?;
        match resp {
            ProtocolMessage::TokenAccepted {
                session_id,
                receiver_session_did,
                ..
            } => {
                // Store session_id for phase 5 (co_sign_receipt)
                if let Ok(mut sid) = self.last_session_id.lock() {
                    *sid = Some(session_id.clone());
                }
                Ok((session_id, receiver_session_did))
            }
            ProtocolMessage::TokenRejected { reason } => Err(TransportError::InvalidResponse(
                format!("Token rejected: {reason}"),
            )),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected response: {other:?}"
            ))),
        }
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        let resp = Self::block_on(
            self.client
                .exchange_did(session_id, initiator_session_did.to_string()),
        )?;
        match resp {
            ProtocolMessage::SessionDidAck => Ok(()),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected DID exchange response: {other:?}"
            ))),
        }
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        let resp = Self::block_on(self.client.send_disclosures(session_id, disclosures))?;
        match resp {
            ProtocolMessage::DisclosureAccepted => Ok(()),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected disclosure response: {other:?}"
            ))),
        }
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let resp = Self::block_on(self.client.request_execution(session_id))?;
        match resp {
            ProtocolMessage::ExecutionResult { result } => Ok(result),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected execution response: {other:?}"
            ))),
        }
    }

    fn co_sign_receipt(
        &self,
        receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        let session_id = self
            .last_session_id
            .lock()
            .ok()
            .and_then(|s| s.clone())
            .ok_or_else(|| {
                TransportError::InvalidResponse(
                    "No session_id — handle_token must be called before co_sign_receipt".into(),
                )
            })?;
        let resp = Self::block_on(self.client.exchange_receipt(&session_id, receipt))?;
        match resp {
            ProtocolMessage::ReceiptCoSigned { receipt } => Ok(receipt),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected receipt response: {other:?}"
            ))),
        }
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        let resp = Self::block_on(self.client.close_session(session_id))?;
        match resp {
            ProtocolMessage::SessionClosed => Ok(()),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected close response: {other:?}"
            ))),
        }
    }
}
