//! OHTTP-wrapped HTTP client for PAP agent handshakes.
//!
//! This module provides an HTTP client that wraps the standard AgentClient
//! to transparently encapsulate/decapsulate PAP protocol messages using
//! RFC 9458 Oblivious HTTP.

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;

use crate::error::TransportError;
use crate::ohttp::{OhttpConfig, OhttpEncryptor};
use crate::server::DEFAULT_MAX_MESSAGE_BYTES;

/// HTTP client for OHTTP-wrapped PAP handshake.
///
/// Wraps AgentClient to transparently encapsulate/decapsulate each phase
/// of the six-phase PAP handshake using RFC 9458 OHTTP.
///
/// If a relay URL is configured, requests go through the relay; otherwise,
/// they connect directly to the origin server.
pub struct OhttpClient {
    origin_url: String,
    relay_url: Option<String>,
    client: reqwest::Client,
    encryptor: OhttpEncryptor,
}

impl OhttpClient {
    /// Create a new OHTTP client pointing to an origin agent server.
    ///
    /// # Arguments
    /// - `origin_url`: Base URL of the agent server (used for key agreement)
    /// - `config`: OHTTP configuration (relay, HPKE suite)
    pub fn new(origin_url: &str, config: OhttpConfig) -> Self {
        let relay_url = config.resolve_relay();
        Self {
            origin_url: origin_url.trim_end_matches('/').to_string(),
            relay_url,
            client: reqwest::Client::new(),
            encryptor: OhttpEncryptor::new(config),
        }
    }

    /// Create an OHTTP client with a pre-configured reqwest client.
    pub fn with_client(origin_url: &str, client: reqwest::Client, config: OhttpConfig) -> Self {
        let relay_url = config.resolve_relay();
        Self {
            origin_url: origin_url.trim_end_matches('/').to_string(),
            relay_url,
            client,
            encryptor: OhttpEncryptor::new(config),
        }
    }

    /// Phase 1: Present a capability token. Returns session_id and
    /// receiver's ephemeral session DID on acceptance.
    pub async fn present_token(
        &self,
        token: CapabilityToken,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::TokenPresentation { token };
        self.send_ohttp_message("/session", msg).await
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
        self.send_ohttp_message(&format!("/session/{}/did", session_id), msg)
            .await
    }

    /// Phase 3: Send selective disclosures (or empty vec for zero-disclosure).
    pub async fn send_disclosures(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::DisclosureOffer { disclosures };
        self.send_ohttp_message(&format!("/session/{}/disclosure", session_id), msg)
            .await
    }

    /// Phase 4: Request execution and receive the result.
    ///
    /// This phase sends an empty POST (no message body).
    pub async fn request_execution(
        &self,
        session_id: &str,
    ) -> Result<ProtocolMessage, TransportError> {
        // Phase 4 doesn't send a message body from initiator.
        // We send an empty JSON object for consistency with OHTTP encapsulation.
        let empty_msg = serde_json::json!({});
        let json_body = serde_json::to_vec(&empty_msg)?;

        // Encapsulate the empty message
        let (encrypted_body, response_ctx) = self.encryptor.encrypt_request(&json_body)?;

        let url = if let Some(ref relay) = self.relay_url {
            format!("{}/session/{}/execute", relay, session_id)
        } else {
            format!("{}/session/{}/execute", self.origin_url, session_id)
        };

        let response = self
            .client
            .post(&url)
            .body(encrypted_body)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let encrypted_resp = response
            .bytes()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))?;

        let json_resp = response_ctx.decrypt_response(&encrypted_resp)?;
        let limit = DEFAULT_MAX_MESSAGE_BYTES;
        // Pre-check: decrypt_response already allocated json_resp; reject before
        // serde_json allocation begins.
        if json_resp.len() > limit {
            return Err(TransportError::MessageTooLarge {
                size: json_resp.len(),
                limit,
            });
        }

        {
            use crate::limited_read::{is_limit_exceeded, LimitedRead};
            use std::io::Cursor;
            serde_json::from_reader(LimitedRead::new(Cursor::new(&json_resp[..]), limit)).map_err(
                |e| {
                    if is_limit_exceeded(&e) {
                        TransportError::MessageTooLarge {
                            size: json_resp.len(),
                            limit,
                        }
                    } else {
                        TransportError::InvalidResponse(e.to_string())
                    }
                },
            )
        }
    }

    /// Phase 5: Send a receipt for co-signing. Returns the co-signed receipt.
    pub async fn exchange_receipt(
        &self,
        session_id: &str,
        receipt: TransactionReceipt,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::ReceiptForCoSign { receipt };
        self.send_ohttp_message(&format!("/session/{}/receipt", session_id), msg)
            .await
    }

    /// Phase 6: Close the session.
    pub async fn close_session(&self, session_id: &str) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::SessionClose {
            session_id: session_id.to_string(),
        };
        self.send_ohttp_message(&format!("/session/{}/close", session_id), msg)
            .await
    }

    /// Send a protocol message via OHTTP encapsulation.
    ///
    /// This is the core method that:
    /// 1. Serializes the message to JSON
    /// 2. Encapsulates it with OHTTP
    /// 3. Sends via relay (if configured) or directly to origin
    /// 4. Decapsulates the response
    /// 5. Deserializes the response message
    async fn send_ohttp_message(
        &self,
        path: &str,
        msg: ProtocolMessage,
    ) -> Result<ProtocolMessage, TransportError> {
        // Step 1: Serialize message to JSON
        let json_body = serde_json::to_vec(&msg)?;

        // Step 2: Encapsulate with OHTTP — returns wire bytes + per-request response context
        let (encrypted_body, response_ctx) = self.encryptor.encrypt_request(&json_body)?;

        // Step 3: Send to relay (if configured) or origin
        let url = if let Some(ref relay) = self.relay_url {
            // Send to relay; it will forward to origin
            format!("{}{}", relay, path)
        } else {
            // Send directly to origin
            format!("{}{}", self.origin_url, path)
        };

        let response = self
            .client
            .post(&url)
            .body(encrypted_body)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        // Step 4: Get encrypted response body
        let encrypted_resp = response
            .bytes()
            .await
            .map_err(|e| TransportError::InvalidResponse(e.to_string()))?;

        // Step 5: Decapsulate response using the per-request context from step 2
        let json_resp = response_ctx.decrypt_response(&encrypted_resp)?;
        let limit = DEFAULT_MAX_MESSAGE_BYTES;
        // Pre-check: decrypt_response already allocated json_resp; reject before
        // serde_json allocation begins.
        if json_resp.len() > limit {
            return Err(TransportError::MessageTooLarge {
                size: json_resp.len(),
                limit,
            });
        }

        // Step 6: Deserialize response message
        {
            use crate::limited_read::{is_limit_exceeded, LimitedRead};
            use std::io::Cursor;
            serde_json::from_reader(LimitedRead::new(Cursor::new(&json_resp[..]), limit)).map_err(
                |e| {
                    if is_limit_exceeded(&e) {
                        TransportError::MessageTooLarge {
                            size: json_resp.len(),
                            limit,
                        }
                    } else {
                        TransportError::InvalidResponse(e.to_string())
                    }
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ohttp_client_new() {
        let config = OhttpConfig::default();
        let client = OhttpClient::new("http://agent.example.com", config);
        assert_eq!(client.origin_url, "http://agent.example.com");
    }

    #[test]
    fn test_ohttp_client_with_relay() {
        let config =
            OhttpConfig::default().with_relay(Some("http://relay.example.com".to_string()));
        let client = OhttpClient::new("http://agent.example.com", config);
        assert_eq!(
            client.relay_url,
            Some("http://relay.example.com".to_string())
        );
    }

    #[test]
    fn test_ohttp_client_trims_trailing_slash() {
        let config = OhttpConfig::default();
        let client = OhttpClient::new("http://agent.example.com/", config);
        assert_eq!(client.origin_url, "http://agent.example.com");
    }
}
