//! Remote agent handler over WebSocket — bridges the sync `AgentHandler`
//! trait to an async `WsAgentClient`.
//!
//! Same pattern as `remote.rs` (HTTP bridge), but for persistent WS
//! connections. The orchestrator's handshake module can treat WS-connected
//! agents identically to local or HTTP-connected ones.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;

use crate::error::TransportError;
use crate::handler::AgentHandler;
use crate::ws_client::WsAgentClient;

/// An `AgentHandler` that delegates to a remote agent over WebSocket.
///
/// Uses `tokio::task::block_in_place` to run async WS operations from
/// within the sync `AgentHandler` trait methods. Wraps `WsAgentClient`
/// in a `Mutex` because WS methods require `&mut self` (stateful stream).
///
/// Stores the capability token's `expires_at` from phase 1 and passes it
/// to all subsequent phase calls for TTL enforcement (spec §5.5).
pub struct WsRemoteAgentHandler {
    client: Mutex<WsAgentClient>,
    last_session_id: Mutex<Option<String>>,
    /// Mandate expiry captured from the capability token during phase 1.
    mandate_expires_at: Mutex<Option<DateTime<Utc>>>,
}

impl WsRemoteAgentHandler {
    /// Create from a pre-connected WebSocket client.
    pub fn new(client: WsAgentClient) -> Self {
        Self {
            client: Mutex::new(client),
            last_session_id: Mutex::new(None),
            mandate_expires_at: Mutex::new(None),
        }
    }

    /// Connect and create.
    pub async fn connect(
        url: &str,
        tls_config: Option<Arc<rustls::ClientConfig>>,
    ) -> Result<Self, TransportError> {
        let client = WsAgentClient::connect(url, tls_config).await?;
        Ok(Self::new(client))
    }

    fn block_on<F: std::future::Future<Output = T>, T>(f: F) -> T {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
    }

    /// Read the stored mandate expiry, returning an error if it was never set.
    fn stored_expires_at(&self) -> Result<DateTime<Utc>, TransportError> {
        self.mandate_expires_at
            .lock()
            .ok()
            .and_then(|g| *g)
            .ok_or_else(|| {
                TransportError::InvalidResponse(
                    "No mandate TTL — handle_token must be called before subsequent phases".into(),
                )
            })
    }
}

impl AgentHandler for WsRemoteAgentHandler {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        // Capture mandate expiry before moving `token` into the request.
        let expires_at = token.expires_at;
        let mut client = self
            .client
            .lock()
            .map_err(|_| TransportError::HandlerError("client lock poisoned".into()))?;
        let resp = Self::block_on(client.present_token(token))?;
        match resp {
            ProtocolMessage::TokenAccepted {
                session_id,
                receiver_session_did,
                ..
            } => {
                if let Ok(mut sid) = self.last_session_id.lock() {
                    *sid = Some(session_id.clone());
                }
                // Store mandate TTL for phases 2-6
                if let Ok(mut ttl) = self.mandate_expires_at.lock() {
                    *ttl = Some(expires_at);
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
        let expires_at = self.stored_expires_at()?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| TransportError::HandlerError("client lock poisoned".into()))?;
        let resp = Self::block_on(client.exchange_did(
            session_id,
            initiator_session_did.to_string(),
            expires_at,
        ))?;
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
        let expires_at = self.stored_expires_at()?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| TransportError::HandlerError("client lock poisoned".into()))?;
        let resp = Self::block_on(client.send_disclosures(session_id, disclosures, expires_at))?;
        match resp {
            ProtocolMessage::DisclosureAccepted => Ok(()),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected disclosure response: {other:?}"
            ))),
        }
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let expires_at = self.stored_expires_at()?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| TransportError::HandlerError("client lock poisoned".into()))?;
        let resp = Self::block_on(client.request_execution(session_id, expires_at))?;
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
        let expires_at = self.stored_expires_at()?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| TransportError::HandlerError("client lock poisoned".into()))?;
        let resp = Self::block_on(client.exchange_receipt(&session_id, receipt, expires_at))?;
        match resp {
            ProtocolMessage::ReceiptCoSigned { receipt } => Ok(receipt),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected receipt response: {other:?}"
            ))),
        }
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        let expires_at = self.stored_expires_at()?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| TransportError::HandlerError("client lock poisoned".into()))?;
        let resp = Self::block_on(client.close_session(session_id, expires_at))?;
        match resp {
            ProtocolMessage::SessionClosed => Ok(()),
            other => Err(TransportError::InvalidResponse(format!(
                "Unexpected close response: {other:?}"
            ))),
        }
    }
}
