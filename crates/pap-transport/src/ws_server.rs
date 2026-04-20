//! WebSocket server for a receiving PAP agent.
//!
//! Accepts WebSocket connections and runs the six-phase handshake
//! protocol over each connection. Each WS connection is one session.

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use pap_proto::ProtocolMessage;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::Message;

use crate::error::TransportError;
use crate::handler::AgentHandler;
use crate::server::DEFAULT_MAX_MESSAGE_BYTES;
use crate::ws_common::{BoxedStream, WsMessage};

/// WebSocket server for a receiving PAP agent.
///
/// Accepts WebSocket connections and dispatches incoming messages to
/// an `AgentHandler`. Each WS connection corresponds to one session.
pub struct WsAgentServer {
    handler: Arc<dyn AgentHandler>,
    port: u16,
    tls_acceptor: Option<TlsAcceptor>,
    /// Maximum allowed size (in bytes) for any single incoming WebSocket frame.
    ///
    /// Frames that exceed this limit are rejected with a
    /// [`TransportError::MessageTooLarge`] error before deserialization begins,
    /// preventing allocation-based DoS attacks.
    /// Defaults to [`DEFAULT_MAX_MESSAGE_BYTES`] (1 MiB).
    max_message_bytes: usize,
}

impl WsAgentServer {
    pub fn new(handler: Arc<dyn AgentHandler>, port: u16) -> Self {
        Self {
            handler,
            port,
            tls_acceptor: None,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }

    /// Enable TLS with a server config (e.g. from `generate_node_identity()`).
    pub fn with_tls(mut self, server_config: Arc<rustls::ServerConfig>) -> Self {
        self.tls_acceptor = Some(TlsAcceptor::from(server_config));
        self
    }

    /// Override the per-frame size limit (bytes).
    ///
    /// Use this for deployments where ExecutionResult payloads routinely
    /// exceed the 1 MiB default (e.g. large JSON-LD documents). Setting a
    /// value of `usize::MAX` effectively disables the check.
    pub fn with_max_message_bytes(mut self, limit: usize) -> Self {
        self.max_message_bytes = limit;
        self
    }

    /// Run the server, binding to the configured port.
    pub async fn run(self) -> Result<(), TransportError> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| TransportError::ServerError(e.to_string()))?;
        self.serve(listener).await
    }

    /// Accept connections on a pre-bound listener.
    ///
    /// Use this in tests with a port-0 listener to discover the OS-assigned port.
    pub async fn serve(self, listener: TcpListener) -> Result<(), TransportError> {
        loop {
            let (tcp, _peer) = listener
                .accept()
                .await
                .map_err(|e| TransportError::ServerError(e.to_string()))?;

            let handler = self.handler.clone();
            let tls_acceptor = self.tls_acceptor.clone();
            let max_message_bytes = self.max_message_bytes;

            tokio::spawn(async move {
                if let Err(e) =
                    handle_connection(tcp, handler, tls_acceptor, max_message_bytes).await
                {
                    eprintln!("WS session error: {e}");
                }
            });
        }
    }
}

/// Handle a single WebSocket connection (one PAP session).
async fn handle_connection(
    tcp: TcpStream,
    handler: Arc<dyn AgentHandler>,
    tls_acceptor: Option<TlsAcceptor>,
    max_message_bytes: usize,
) -> Result<(), TransportError> {
    // Step 1: Optional TLS upgrade
    let stream: BoxedStream = if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor
            .accept(tcp)
            .await
            .map_err(|e| TransportError::ConnectionFailed(format!("TLS accept failed: {e}")))?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    // Step 2: WebSocket upgrade
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| TransportError::WebSocketError(format!("WS accept failed: {e}")))?;

    let (mut ws_tx, mut ws_rx) = ws.split();

    // Step 3: Session state — tracks the session_id across phases
    let mut session_id: Option<String> = None;

    // Step 4: Message loop
    while let Some(msg_result) = ws_rx.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                // Connection-level errors are not recoverable
                return Err(TransportError::WebSocketError(e.to_string()));
            }
        };

        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            Message::Ping(data) => {
                let _ = ws_tx.send(Message::Pong(data)).await;
                continue;
            }
            _ => continue,
        };

        // Reject frames that exceed the per-frame size limit before any
        // deserialization work is performed.  This prevents an attacker from
        // exhausting server memory by sending arbitrarily large JSON frames.
        if text.len() > max_message_bytes {
            return Err(TransportError::MessageTooLarge {
                size: text.len(),
                limit: max_message_bytes,
            });
        }

        let ws_msg: WsMessage = serde_json::from_str(&text)
            .map_err(|e| TransportError::InvalidResponse(format!("deserialize failed: {e}")))?;

        let response = dispatch_message(&handler, &mut session_id, ws_msg)?;
        let is_close = matches!(&response.payload, Some(ProtocolMessage::SessionClosed));

        let json = serde_json::to_string(&response)
            .map_err(|e| TransportError::ServerError(e.to_string()))?;

        ws_tx
            .send(Message::Text(json.into()))
            .await
            .map_err(|e| TransportError::WebSocketError(format!("send failed: {e}")))?;

        if is_close {
            let _ = ws_tx.close().await;
            break;
        }
    }

    Ok(())
}

/// Dispatch a `WsMessage` to the appropriate `AgentHandler` method.
///
/// Mirrors the Axum route handlers in `server.rs` but uses the `phase`
/// field for routing instead of URL paths.
fn dispatch_message(
    handler: &Arc<dyn AgentHandler>,
    session_id: &mut Option<String>,
    msg: WsMessage,
) -> Result<WsMessage, TransportError> {
    match msg.phase {
        // Phase 1: Token presentation
        1 => {
            let payload = msg.payload.ok_or_else(|| {
                TransportError::InvalidResponse("phase 1: missing payload".into())
            })?;
            match payload {
                ProtocolMessage::TokenPresentation { token } => match handler.handle_token(token) {
                    Ok((sid, receiver_did)) => {
                        *session_id = Some(sid.clone());
                        Ok(WsMessage {
                            phase: 1,
                            session_id: Some(sid.clone()),
                            payload: Some(ProtocolMessage::TokenAccepted {
                                session_id: sid,
                                receiver_session_did: receiver_did,
                                attestation: None,
                            }),
                        })
                    }
                    Err(e) => Ok(WsMessage {
                        phase: 1,
                        session_id: None,
                        payload: Some(ProtocolMessage::TokenRejected {
                            reason: e.to_string(),
                        }),
                    }),
                },
                _ => Err(TransportError::InvalidResponse(
                    "phase 1: expected TokenPresentation".into(),
                )),
            }
        }

        // Phase 2: Ephemeral DID exchange
        2 => {
            let sid = require_session_id(session_id)?;
            let payload = msg.payload.ok_or_else(|| {
                TransportError::InvalidResponse("phase 2: missing payload".into())
            })?;
            match payload {
                ProtocolMessage::SessionDidExchange {
                    initiator_session_did,
                } => {
                    handler.handle_did_exchange(&sid, &initiator_session_did)?;
                    Ok(WsMessage {
                        phase: 2,
                        session_id: Some(sid),
                        payload: Some(ProtocolMessage::SessionDidAck),
                    })
                }
                _ => Err(TransportError::InvalidResponse(
                    "phase 2: expected SessionDidExchange".into(),
                )),
            }
        }

        // Phase 3: Disclosure
        3 => {
            let sid = require_session_id(session_id)?;
            let payload = msg.payload.ok_or_else(|| {
                TransportError::InvalidResponse("phase 3: missing payload".into())
            })?;
            match payload {
                ProtocolMessage::DisclosureOffer { disclosures } => {
                    handler.handle_disclosure(&sid, disclosures)?;
                    Ok(WsMessage {
                        phase: 3,
                        session_id: Some(sid),
                        payload: Some(ProtocolMessage::DisclosureAccepted),
                    })
                }
                _ => Err(TransportError::InvalidResponse(
                    "phase 3: expected DisclosureOffer".into(),
                )),
            }
        }

        // Phase 4: Execute or streaming message frame.
        //
        // - No payload → initial execute (existing behaviour).
        // - StreamingMessage payload → bidirectional streaming (e.g. chat).
        4 => {
            let sid = require_session_id(session_id)?;
            match &msg.payload {
                None => {
                    // Standard task execution — returns ExecutionResult.
                    let result = handler.execute(&sid)?;
                    Ok(WsMessage {
                        phase: 4,
                        session_id: Some(sid),
                        payload: Some(ProtocolMessage::ExecutionResult { result }),
                    })
                }
                Some(ProtocolMessage::StreamingMessage { id, content }) => {
                    // Streaming frame — delegate to handler, reply with frame or ack.
                    let reply = handler.handle_stream_message(&sid, id, content)?;
                    let payload = match reply {
                        Some(body) => ProtocolMessage::StreamingMessage {
                            id: uuid::Uuid::new_v4().to_string(),
                            content: body,
                        },
                        None => ProtocolMessage::StreamingAck { id: id.clone() },
                    };
                    Ok(WsMessage {
                        phase: 4,
                        session_id: Some(sid),
                        payload: Some(payload),
                    })
                }
                _ => Err(TransportError::InvalidResponse(
                    "phase 4: unexpected payload type".into(),
                )),
            }
        }

        // Phase 5: Receipt co-signing
        5 => {
            let sid = require_session_id(session_id)?;
            let payload = msg.payload.ok_or_else(|| {
                TransportError::InvalidResponse("phase 5: missing payload".into())
            })?;
            match payload {
                ProtocolMessage::ReceiptForCoSign { receipt } => {
                    let signed = handler.co_sign_receipt(receipt)?;
                    Ok(WsMessage {
                        phase: 5,
                        session_id: Some(sid),
                        payload: Some(ProtocolMessage::ReceiptCoSigned { receipt: signed }),
                    })
                }
                _ => Err(TransportError::InvalidResponse(
                    "phase 5: expected ReceiptForCoSign".into(),
                )),
            }
        }

        // Phase 6: Close
        6 => {
            let sid = require_session_id(session_id)?;
            handler.handle_close(&sid)?;
            Ok(WsMessage {
                phase: 6,
                session_id: Some(sid),
                payload: Some(ProtocolMessage::SessionClosed),
            })
        }

        other => Err(TransportError::InvalidResponse(format!(
            "unknown phase: {other}"
        ))),
    }
}

fn require_session_id(session_id: &Option<String>) -> Result<String, TransportError> {
    session_id.clone().ok_or_else(|| {
        TransportError::InvalidResponse("no session established (phase 1 not completed)".into())
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pap_core::{receipt::TransactionReceipt, session::CapabilityToken};
    use pap_proto::ProtocolMessage;

    use super::*;
    use crate::ws_common::WsMessage;

    // ── Minimal stub handlers ─────────────────────────────────────────────

    /// Handler whose execute() returns a SearchResult (no streaming support).
    struct BasicHandler;
    impl AgentHandler for BasicHandler {
        fn handle_token(&self, _: CapabilityToken) -> Result<(String, String), TransportError> {
            Ok(("sess-basic".into(), "did:key:zBasic".into()))
        }
        fn handle_did_exchange(&self, _: &str, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
        fn handle_disclosure(
            &self,
            _: &str,
            _: Vec<serde_json::Value>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
        fn execute(&self, _: &str) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::json!({"@type": "SearchResult", "name": "test"}))
        }
        fn co_sign_receipt(
            &self,
            r: TransactionReceipt,
        ) -> Result<TransactionReceipt, TransportError> {
            Ok(r)
        }
        fn handle_close(&self, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// Handler that echoes streaming messages back to the caller.
    struct EchoStreamHandler;
    impl AgentHandler for EchoStreamHandler {
        fn handle_token(&self, _: CapabilityToken) -> Result<(String, String), TransportError> {
            Ok(("sess-echo".into(), "did:key:zEcho".into()))
        }
        fn handle_did_exchange(&self, _: &str, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
        fn handle_disclosure(
            &self,
            _: &str,
            _: Vec<serde_json::Value>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
        fn execute(&self, _: &str) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::json!({"@type": "Conversation", "identifier": "room-1"}))
        }
        fn handle_stream_message(
            &self,
            _: &str,
            _: &str,
            content: &serde_json::Value,
        ) -> Result<Option<serde_json::Value>, TransportError> {
            Ok(Some(content.clone())) // echo
        }
        fn co_sign_receipt(
            &self,
            r: TransactionReceipt,
        ) -> Result<TransactionReceipt, TransportError> {
            Ok(r)
        }
        fn handle_close(&self, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// Handler that ack-only responds to streaming messages.
    struct AckOnlyHandler;
    impl AgentHandler for AckOnlyHandler {
        fn handle_token(&self, _: CapabilityToken) -> Result<(String, String), TransportError> {
            Ok(("sess-ack".into(), "did:key:zAck".into()))
        }
        fn handle_did_exchange(&self, _: &str, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
        fn handle_disclosure(
            &self,
            _: &str,
            _: Vec<serde_json::Value>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
        fn execute(&self, _: &str) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::Value::Null)
        }
        fn handle_stream_message(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
        ) -> Result<Option<serde_json::Value>, TransportError> {
            Ok(None) // ack-only
        }
        fn co_sign_receipt(
            &self,
            r: TransactionReceipt,
        ) -> Result<TransactionReceipt, TransportError> {
            Ok(r)
        }
        fn handle_close(&self, _: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn arc<H: AgentHandler + 'static>(h: H) -> Arc<dyn AgentHandler> {
        Arc::new(h)
    }

    // ── Phase 4 dispatch tests ────────────────────────────────────────────

    #[test]
    fn phase4_no_payload_calls_execute() {
        let h = arc(BasicHandler);
        let mut sid = Some("sess-basic".to_string());
        let msg = WsMessage {
            phase: 4,
            session_id: Some("sess-basic".into()),
            payload: None,
        };
        let resp = dispatch_message(&h, &mut sid, msg).unwrap();
        assert_eq!(resp.phase, 4);
        match resp.payload {
            Some(ProtocolMessage::ExecutionResult { result }) => {
                assert_eq!(result["@type"], "SearchResult");
            }
            _ => panic!("expected ExecutionResult"),
        }
    }

    #[test]
    fn phase4_streaming_message_echoed_back() {
        let h = arc(EchoStreamHandler);
        let mut sid = Some("sess-echo".to_string());
        let content = serde_json::json!({"body": {"content": "hello chat"}});
        let msg = WsMessage {
            phase: 4,
            session_id: Some("sess-echo".into()),
            payload: Some(ProtocolMessage::StreamingMessage {
                id: "msg-abc".into(),
                content: content.clone(),
            }),
        };
        let resp = dispatch_message(&h, &mut sid, msg).unwrap();
        assert_eq!(resp.phase, 4);
        match resp.payload {
            Some(ProtocolMessage::StreamingMessage { content: reply, .. }) => {
                assert_eq!(reply, content);
            }
            _ => panic!("expected StreamingMessage reply"),
        }
    }

    #[test]
    fn phase4_streaming_ack_when_handler_returns_none() {
        let h = arc(AckOnlyHandler);
        let mut sid = Some("sess-ack".to_string());
        let msg = WsMessage {
            phase: 4,
            session_id: Some("sess-ack".into()),
            payload: Some(ProtocolMessage::StreamingMessage {
                id: "msg-42".into(),
                content: serde_json::json!({}),
            }),
        };
        let resp = dispatch_message(&h, &mut sid, msg).unwrap();
        match resp.payload {
            Some(ProtocolMessage::StreamingAck { id }) => assert_eq!(id, "msg-42"),
            _ => panic!("expected StreamingAck"),
        }
    }

    #[test]
    fn phase4_streaming_error_when_unsupported() {
        // BasicHandler uses the default handle_stream_message → returns error
        let h = arc(BasicHandler);
        let mut sid = Some("sess-basic".to_string());
        let msg = WsMessage {
            phase: 4,
            session_id: Some("sess-basic".into()),
            payload: Some(ProtocolMessage::StreamingMessage {
                id: "msg-x".into(),
                content: serde_json::json!({}),
            }),
        };
        assert!(dispatch_message(&h, &mut sid, msg).is_err());
    }

    #[test]
    fn phase4_unexpected_payload_type_returns_error() {
        let h = arc(BasicHandler);
        let mut sid = Some("sess-basic".to_string());
        let msg = WsMessage {
            phase: 4,
            session_id: Some("sess-basic".into()),
            payload: Some(ProtocolMessage::SessionClosed), // wrong type for phase 4
        };
        assert!(dispatch_message(&h, &mut sid, msg).is_err());
    }

    #[test]
    fn phase4_requires_established_session() {
        let h = arc(BasicHandler);
        let mut sid: Option<String> = None; // no session yet
        let msg = WsMessage {
            phase: 4,
            session_id: None,
            payload: None,
        };
        assert!(dispatch_message(&h, &mut sid, msg).is_err());
    }

    // ── Per-frame size-limit tests ────────────────────────────────────────

    /// Send a frame whose byte length exceeds the configured limit and verify
    /// the server closes the connection (returns a WS error or close frame).
    #[tokio::test]
    async fn ws_frame_exceeding_limit_is_rejected() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::Message;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server with a tiny 32-byte limit — any real PAP frame will exceed it.
        let server = WsAgentServer::new(arc(BasicHandler), addr.port()).with_max_message_bytes(32);
        tokio::spawn(async move { server.serve(listener).await });

        let url = format!("ws://{addr}");
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Build a frame that is definitely larger than 32 bytes.
        let oversized = "x".repeat(1024);
        let _ = ws.send(Message::Text(oversized.into())).await;

        // The server should close the connection — we expect either a Close
        // frame or an error on the next read.
        let result = ws.next().await;
        let is_closed = match result {
            None => true, // stream ended
            Some(Ok(Message::Close(_))) => true,
            Some(Err(_)) => true,
            Some(Ok(_)) => false,
        };
        assert!(
            is_closed,
            "expected connection to be closed after oversized frame"
        );
    }

    /// A frame within the configured limit must be processed normally.
    #[tokio::test]
    async fn ws_frame_within_limit_is_accepted() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::Message;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server with the default (generous) limit.
        let server = WsAgentServer::new(arc(BasicHandler), addr.port());
        tokio::spawn(async move { server.serve(listener).await });

        let url = format!("ws://{addr}");
        let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Send a valid phase-1 frame (small, well within the default limit).
        let token_json = serde_json::json!({
            "phase": 1,
            "payload": {
                "type": "TokenPresentation",
                "token": {
                    "id": "t1",
                    "target_did": "did:key:zDEF",
                    "action": "schema:SearchAction",
                    "nonce": "test-nonce",
                    "issuer_did": "did:key:zABC",
                    "issued_at": "2025-01-01T00:00:00Z",
                    "expires_at": "2099-01-01T00:00:00Z"
                }
            }
        });
        ws.send(Message::Text(token_json.to_string().into()))
            .await
            .unwrap();

        // The server should respond (not close with an error).
        let reply = ws.next().await.unwrap().unwrap();
        assert!(matches!(reply, Message::Text(_)));
    }
}
