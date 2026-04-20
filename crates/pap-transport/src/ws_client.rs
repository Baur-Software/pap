//! WebSocket client for an initiating PAP agent.
//!
//! Drives the six-phase handshake over a single persistent WebSocket
//! connection. Messages are `ProtocolMessage` wrapped in a `WsMessage`
//! envelope and sent as JSON text frames.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
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
        use crate::limited_read::{is_limit_exceeded, LimitedRead};
        use crate::server::DEFAULT_MAX_MESSAGE_BYTES;
        use std::io::Cursor;
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
            Message::Text(text) => {
                let limit = DEFAULT_MAX_MESSAGE_BYTES;
                serde_json::from_reader(LimitedRead::new(Cursor::new(text.as_bytes()), limit))
                    .map_err(|e| {
                        if is_limit_exceeded(&e) {
                            TransportError::MessageTooLarge {
                                size: text.len(),
                                limit,
                            }
                        } else {
                            TransportError::InvalidResponse(format!("deserialize failed: {e}"))
                        }
                    })
            }
            Message::Close(frame) => {
                // RFC 6455 §7.4.1 close code 1009 (Size) means the server
                // rejected our frame as too large.
                let is_too_large = frame
                    .as_ref()
                    .map(|f| f.code == CloseCode::Size)
                    .unwrap_or(false);
                if is_too_large {
                    Err(TransportError::MessageTooLarge {
                        size: 0,
                        limit: DEFAULT_MAX_MESSAGE_BYTES,
                    })
                } else {
                    Err(TransportError::ConnectionFailed(
                        "peer closed connection".into(),
                    ))
                }
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
    ///
    /// `mandate_expires_at` is checked before the message is sent.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn exchange_did(
        &mut self,
        session_id: &str,
        initiator_session_did: String,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        if Utc::now() > mandate_expires_at {
            return Err(TransportError::MandateExpired);
        }
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
    ///
    /// `mandate_expires_at` is checked before the message is sent.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn send_disclosures(
        &mut self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        if Utc::now() > mandate_expires_at {
            return Err(TransportError::MandateExpired);
        }
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
    ///
    /// `mandate_expires_at` is checked before the message is sent.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn request_execution(
        &mut self,
        session_id: &str,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        if Utc::now() > mandate_expires_at {
            return Err(TransportError::MandateExpired);
        }
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

    /// Phase 4 streaming: send a DIDComm basicmessage frame over an open
    /// streaming session.
    ///
    /// Call this after `request_execution()` returns `ExecutionResult` that
    /// signals a streaming session is open (e.g. a `schema:Conversation`).
    /// Returns `StreamingAck` or a `StreamingMessage` reply from the server.
    pub async fn send_stream_message(
        &mut self,
        session_id: &str,
        content: serde_json::Value,
    ) -> Result<ProtocolMessage, TransportError> {
        let id = uuid::Uuid::new_v4().to_string();
        let resp = self
            .send_recv(WsMessage {
                phase: 4,
                session_id: Some(session_id.to_string()),
                payload: Some(ProtocolMessage::StreamingMessage {
                    id: id.clone(),
                    content,
                }),
            })
            .await?;
        resp.payload.ok_or_else(|| {
            TransportError::InvalidResponse("streaming: missing response payload".into())
        })
    }

    /// Phase 5: Send receipt for co-signing.
    ///
    /// `mandate_expires_at` is checked before the message is sent.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn exchange_receipt(
        &mut self,
        session_id: &str,
        receipt: TransactionReceipt,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        if Utc::now() > mandate_expires_at {
            return Err(TransportError::MandateExpired);
        }
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
    ///
    /// `mandate_expires_at` is checked before the message is sent.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn close_session(
        &mut self,
        session_id: &str,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        if Utc::now() > mandate_expires_at {
            return Err(TransportError::MandateExpired);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::DEFAULT_MAX_MESSAGE_BYTES;

    // ── LimitedRead integration: WsAgentClient response path ─────────────

    /// A raw WebSocket server that immediately sends one oversized text frame
    /// after the WS handshake, then closes.  Used to verify that the client
    /// rejects the frame with `MessageTooLarge` rather than allocating it.
    async fn serve_oversized_response(listener: tokio::net::TcpListener) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        if let Ok((tcp, _)) = listener.accept().await {
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            // Consume the client's first message (phase-1 token frame).
            let _ = ws.next().await;
            // Reply with an oversized frame.
            // Must be valid JSON so serde_json parses past the first byte before
            // LimitedRead trips.  A JSON string value fills the buffer cleanly.
            let payload = "a".repeat(2 * DEFAULT_MAX_MESSAGE_BYTES);
            let big = format!(r#"{{"t":"{}"}}"#, payload);
            let _ = ws.send(Message::Text(big.into())).await;
        }
    }

    /// When the server sends a frame larger than `DEFAULT_MAX_MESSAGE_BYTES`
    /// the client must return `Err(TransportError::MessageTooLarge { .. })`.
    #[tokio::test]
    async fn ws_client_oversized_response_rejected() {
        use chrono::{Duration, Utc};
        use pap_core::session::CapabilityToken;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(serve_oversized_response(listener));

        let url = format!("ws://{addr}");
        let mut client = WsAgentClient::connect_plain(&url).await.unwrap();

        let token = CapabilityToken::mint(
            "did:key:zReceiver".into(),
            "schema:SearchAction".into(),
            "did:key:zIssuer".into(),
            Utc::now() + Duration::hours(1),
        );

        let result = client.present_token(token).await;
        assert!(
            matches!(result, Err(TransportError::MessageTooLarge { .. })),
            "expected MessageTooLarge, got: {result:?}"
        );
    }
}
