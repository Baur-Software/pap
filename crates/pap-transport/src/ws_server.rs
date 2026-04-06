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
use crate::ws_common::{BoxedStream, WsMessage};

/// WebSocket server for a receiving PAP agent.
///
/// Accepts WebSocket connections and dispatches incoming messages to
/// an `AgentHandler`. Each WS connection corresponds to one session.
pub struct WsAgentServer {
    handler: Arc<dyn AgentHandler>,
    port: u16,
    tls_acceptor: Option<TlsAcceptor>,
}

impl WsAgentServer {
    pub fn new(handler: Arc<dyn AgentHandler>, port: u16) -> Self {
        Self {
            handler,
            port,
            tls_acceptor: None,
        }
    }

    /// Enable TLS with a server config (e.g. from `generate_node_identity()`).
    pub fn with_tls(mut self, server_config: Arc<rustls::ServerConfig>) -> Self {
        self.tls_acceptor = Some(TlsAcceptor::from(server_config));
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

            tokio::spawn(async move {
                if let Err(e) = handle_connection(tcp, handler, tls_acceptor).await {
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
