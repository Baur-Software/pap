//! WebSocket client for an initiating PAP agent.
//!
//! Drives the six-phase handshake over a single persistent WebSocket
//! connection. Messages are `ProtocolMessage` wrapped in a `WsMessage`
//! envelope and sent as JSON text frames.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::error::TransportError;
use crate::ws_common::{BoxedStream, WsMessage};

/// WebSocket client for an initiating PAP agent.
///
/// Drives the six-phase handshake over a single persistent WebSocket
/// connection. Each instance is bound to one session — connect, run
/// all six phases, then drop.
pub struct WsAgentClient {
    ws: WebSocketStream<BoxedStream>,
}

/// Parse scheme, host, and port from a ws:// or wss:// URL.
fn parse_ws_url(url: &str) -> Result<(&str, String, u16), TransportError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| TransportError::ConnectionFailed("missing :// in URL".into()))?;

    // Strip path portion (everything after host:port)
    let authority = rest.split('/').next().unwrap_or(rest);

    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        let port: u16 = p
            .parse()
            .map_err(|_| TransportError::ConnectionFailed(format!("invalid port: {p}")))?;
        (h.to_string(), port)
    } else {
        let default_port = match scheme {
            "wss" => 443,
            "ws" => 80,
            _ => {
                return Err(TransportError::ConnectionFailed(format!(
                    "unsupported scheme: {scheme}"
                )))
            }
        };
        (authority.to_string(), default_port)
    };

    Ok((scheme, host, port))
}

impl WsAgentClient {
    /// Connect to a WebSocket endpoint.
    ///
    /// For `wss://` URLs, provide a `rustls::ClientConfig` (e.g. from
    /// `pap_federation::build_pinned_tls_config()`). For `ws://` URLs
    /// (tests only), pass `None`.
    pub async fn connect(
        url: &str,
        tls_config: Option<Arc<rustls::ClientConfig>>,
    ) -> Result<Self, TransportError> {
        let (scheme, host, port) = parse_ws_url(url)?;

        let tcp = TcpStream::connect(format!("{host}:{port}"))
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        let stream: BoxedStream = if scheme == "wss" {
            let config = tls_config.ok_or_else(|| {
                TransportError::ConnectionFailed("wss:// requires TLS config".into())
            })?;
            let connector = TlsConnector::from(config);
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| {
                    TransportError::ConnectionFailed(format!("invalid server name: {e}"))
                })?;
            let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
                TransportError::ConnectionFailed(format!("TLS handshake failed: {e}"))
            })?;
            Box::new(tls_stream)
        } else {
            Box::new(tcp)
        };

        let (ws, _response) = tokio_tungstenite::client_async(url, stream)
            .await
            .map_err(|e| TransportError::WebSocketError(format!("WS handshake failed: {e}")))?;

        Ok(Self { ws })
    }

    /// Connect without TLS (for loopback tests).
    pub async fn connect_plain(url: &str) -> Result<Self, TransportError> {
        Self::connect(url, None).await
    }

    /// Send a `WsMessage` and receive the response.
    async fn send_recv(&mut self, msg: WsMessage) -> Result<WsMessage, TransportError> {
        let json = serde_json::to_string(&msg)
            .map_err(|e| TransportError::RequestFailed(format!("serialize failed: {e}")))?;

        self.ws
            .send(Message::Text(json.into()))
            .await
            .map_err(|e| TransportError::WebSocketError(format!("send failed: {e}")))?;

        let response = self
            .ws
            .next()
            .await
            .ok_or_else(|| TransportError::ConnectionFailed("connection closed".into()))?
            .map_err(|e| TransportError::WebSocketError(format!("receive failed: {e}")))?;

        match response {
            Message::Text(text) => serde_json::from_str(&text)
                .map_err(|e| TransportError::InvalidResponse(format!("deserialize failed: {e}"))),
            Message::Close(_) => {
                Err(TransportError::ConnectionFailed("peer closed connection".into()))
            }
            other => Err(TransportError::InvalidResponse(format!(
                "expected text frame, got: {other:?}"
            ))),
        }
    }

    /// Phase 1: Present a capability token.
    pub async fn present_token(
        &mut self,
        token: CapabilityToken,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .send_recv(WsMessage {
                phase: 1,
                session_id: None,
                payload: Some(ProtocolMessage::TokenPresentation { token }),
            })
            .await?;
        resp.payload
            .ok_or_else(|| TransportError::InvalidResponse("phase 1: missing payload".into()))
    }

    /// Phase 2: Exchange ephemeral session DID.
    pub async fn exchange_did(
        &mut self,
        session_id: &str,
        initiator_session_did: String,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .send_recv(WsMessage {
                phase: 2,
                session_id: Some(session_id.to_string()),
                payload: Some(ProtocolMessage::SessionDidExchange {
                    initiator_session_did,
                }),
            })
            .await?;
        resp.payload
            .ok_or_else(|| TransportError::InvalidResponse("phase 2: missing payload".into()))
    }

    /// Phase 3: Send selective disclosures (or empty vec for zero-disclosure).
    pub async fn send_disclosures(
        &mut self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .send_recv(WsMessage {
                phase: 3,
                session_id: Some(session_id.to_string()),
                payload: Some(ProtocolMessage::DisclosureOffer { disclosures }),
            })
            .await?;
        resp.payload
            .ok_or_else(|| TransportError::InvalidResponse("phase 3: missing payload".into()))
    }

    /// Phase 4: Request execution. No client payload (mirrors HTTP empty POST).
    pub async fn request_execution(
        &mut self,
        session_id: &str,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .send_recv(WsMessage {
                phase: 4,
                session_id: Some(session_id.to_string()),
                payload: None,
            })
            .await?;
        resp.payload
            .ok_or_else(|| TransportError::InvalidResponse("phase 4: missing payload".into()))
    }

    /// Phase 5: Send receipt for co-signing.
    pub async fn exchange_receipt(
        &mut self,
        session_id: &str,
        receipt: TransactionReceipt,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .send_recv(WsMessage {
                phase: 5,
                session_id: Some(session_id.to_string()),
                payload: Some(ProtocolMessage::ReceiptForCoSign { receipt }),
            })
            .await?;
        resp.payload
            .ok_or_else(|| TransportError::InvalidResponse("phase 5: missing payload".into()))
    }

    /// Phase 6: Close session.
    ///
    /// Sends `SessionClose`, receives `SessionClosed`, then sends a WS close frame.
    pub async fn close_session(
        &mut self,
        session_id: &str,
    ) -> Result<ProtocolMessage, TransportError> {
        let resp = self
            .send_recv(WsMessage {
                phase: 6,
                session_id: Some(session_id.to_string()),
                payload: Some(ProtocolMessage::SessionClose {
                    session_id: session_id.to_string(),
                }),
            })
            .await?;

        // After receiving SessionClosed, send WS close frame
        let _ = self.ws.close(None).await;

        resp.payload
            .ok_or_else(|| TransportError::InvalidResponse("phase 6: missing payload".into()))
    }
}
