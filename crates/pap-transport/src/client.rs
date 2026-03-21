use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;

use crate::error::TransportError;

/// HTTP client for an initiating PAP agent.
///
/// Drives the six-phase handshake by sending protocol messages to
/// a receiving agent's HTTP server.
pub struct AgentClient {
    base_url: String,
    client: reqwest::Client,
}

impl AgentClient {
    /// Create a new agent client with standard TLS settings.
    ///
    /// Uses system CA roots. For PAP federation connections (self-signed
    /// certs), use `with_client()` with a fingerprint-pinned reqwest
    /// client from `pap_federation::build_pinned_client()`.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create an agent client with a pre-configured reqwest client.
    ///
    /// Use this when you need a client with specific TLS settings,
    /// e.g. pinned peer certificate fingerprints.
    pub fn with_client(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Phase 1: Present a capability token. Returns session_id and
    /// receiver's ephemeral session DID on acceptance.
    pub async fn present_token(
        &self,
        token: CapabilityToken,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::TokenPresentation { token };
        let resp = self
            .client
            .post(format!("{}/session", self.base_url))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        resp.json::<ProtocolMessage>()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }

    /// Phase 2: Send the initiator's ephemeral session DID.
    pub async fn exchange_did(
        &self,
        session_id: &str,
        initiator_session_did: String,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        };
        let resp = self
            .client
            .post(format!("{}/session/{}/did", self.base_url, session_id))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        resp.json::<ProtocolMessage>()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }

    /// Phase 3: Send selective disclosures (or empty vec for zero-disclosure).
    pub async fn send_disclosures(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::DisclosureOffer { disclosures };
        let resp = self
            .client
            .post(format!(
                "{}/session/{}/disclosure",
                self.base_url, session_id
            ))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        resp.json::<ProtocolMessage>()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }

    /// Phase 4: Request execution and receive the result.
    pub async fn request_execution(
        &self,
        session_id: &str,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .client
            .post(format!("{}/session/{}/execute", self.base_url, session_id))
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        resp.json::<ProtocolMessage>()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }

    /// Phase 5: Send a receipt for co-signing. Returns the co-signed receipt.
    pub async fn exchange_receipt(
        &self,
        session_id: &str,
        receipt: TransactionReceipt,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::ReceiptForCoSign { receipt };
        let resp = self
            .client
            .post(format!("{}/session/{}/receipt", self.base_url, session_id))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        resp.json::<ProtocolMessage>()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }

    /// Phase 6: Close the session.
    pub async fn close_session(&self, session_id: &str) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::SessionClose {
            session_id: session_id.to_string(),
        };
        let resp = self
            .client
            .post(format!("{}/session/{}/close", self.base_url, session_id))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        resp.json::<ProtocolMessage>()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))
    }
}
