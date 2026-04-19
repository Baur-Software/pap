//! PAP agent receiver over a BlueField RDMA channel.
//!
//! [`BluefieldServer`] accepts incoming RDMA connections (via TCP bootstrap)
//! and drives each connection through the six-phase PAP handshake, calling
//! the caller-supplied [`pap_transport::AgentHandler`] for each phase.
//!
//! The `handle_channel` free function is public so unit tests in `client.rs`
//! (and elsewhere) can run a server-side loop over a [`MockChannel`] pair
//! without needing real BlueField hardware.

use std::sync::Arc;

use pap_proto::ProtocolMessage;
use pap_transport::AgentHandler;

use crate::channel::MessageChannel;
use crate::error::BluefieldError;

// ── Server ────────────────────────────────────────────────────────────────────

/// Receives RDMA connections and dispatches PAP phases to an [`AgentHandler`].
///
/// Each accepted connection is run in a dedicated Tokio task.  Errors inside
/// a single session are logged but do not bring down the server.
#[cfg(feature = "rdma")]
pub struct BluefieldServer<H: AgentHandler + 'static> {
    handler: Arc<H>,
    bootstrap_port: u16,
}

#[cfg(feature = "rdma")]
impl<H: AgentHandler + 'static> BluefieldServer<H> {
    pub fn new(handler: Arc<H>, bootstrap_port: u16) -> Self {
        Self {
            handler,
            bootstrap_port,
        }
    }

    /// Run the server: bind the RDMA bootstrap TCP port and accept connections
    /// indefinitely.
    ///
    /// Each accepted connection is handled in its own `tokio::spawn` task.
    pub async fn run(
        self,
        dev: Arc<crate::rdma::context::DeviceContext>,
    ) -> Result<(), BluefieldError> {
        let server = crate::rdma::connection::RdmaBootstrapServer::bind(
            self.bootstrap_port,
            Arc::clone(&dev),
        )
        .await?;

        loop {
            match server.accept().await {
                Ok(conn) => {
                    let handler = Arc::clone(&self.handler);
                    tokio::spawn(async move {
                        if let Err(e) = handle_channel(handler, conn).await {
                            eprintln!("BlueField session error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("BlueField accept error: {e}");
                }
            }
        }
    }
}

// ── Per-connection handler loop ───────────────────────────────────────────────

/// Run the six-phase PAP protocol on `channel`, dispatching to `handler`.
///
/// This is the single connection handler used by [`BluefieldServer::run`] and
/// directly by tests using [`crate::channel::MockChannel`] pairs.
pub async fn handle_channel<C: MessageChannel, H: AgentHandler>(
    handler: Arc<H>,
    mut channel: C,
) -> Result<(), BluefieldError> {
    let mut session_id: Option<String> = None;

    loop {
        let msg = channel.recv_msg().await?;
        let reply = dispatch(&handler, &mut session_id, msg)?;
        let is_closed = matches!(&reply, ProtocolMessage::SessionClosed);
        channel.send_msg(&reply).await?;
        if is_closed {
            break;
        }
    }

    Ok(())
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/// Map an incoming [`ProtocolMessage`] to the appropriate [`AgentHandler`]
/// method and return the reply message.
fn dispatch<H: AgentHandler>(
    handler: &Arc<H>,
    session_id: &mut Option<String>,
    msg: ProtocolMessage,
) -> Result<ProtocolMessage, BluefieldError> {
    match msg {
        // ── Phase 1: Token presentation ───────────────────────────────────
        ProtocolMessage::TokenPresentation { token } => match handler.handle_token(token) {
            Ok((sid, receiver_did)) => {
                *session_id = Some(sid.clone());
                Ok(ProtocolMessage::TokenAccepted {
                    session_id: sid,
                    receiver_session_did: receiver_did,
                    attestation: None,
                })
            }
            Err(e) => Ok(ProtocolMessage::TokenRejected {
                reason: e.to_string(),
            }),
        },

        // ── Phase 2: DID exchange ─────────────────────────────────────────
        ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        } => {
            let sid = require_session(session_id)?;
            handler
                .handle_did_exchange(&sid, &initiator_session_did)
                .map_err(|e| BluefieldError::ProtocolError(e.to_string()))?;
            Ok(ProtocolMessage::SessionDidAck)
        }

        // ── Phase 3: Disclosure ───────────────────────────────────────────
        ProtocolMessage::DisclosureOffer { disclosures } => {
            let sid = require_session(session_id)?;
            handler
                .handle_disclosure(&sid, disclosures)
                .map_err(|e| BluefieldError::ProtocolError(e.to_string()))?;
            Ok(ProtocolMessage::DisclosureAccepted)
        }

        // ── Phase 4: Execute (triggered by SessionDidAck sentinel) ────────
        // The client sends SessionDidAck as a zero-payload execution trigger.
        // handler.execute() is synchronous; call it directly.
        ProtocolMessage::SessionDidAck => {
            let sid = require_session(session_id)?;
            let result = handler
                .execute(&sid)
                .map_err(|e| BluefieldError::ProtocolError(e.to_string()))?;
            Ok(ProtocolMessage::ExecutionResult { result })
        }

        // ── Phase 5: Receipt co-signing ───────────────────────────────────
        ProtocolMessage::ReceiptForCoSign { receipt } => {
            let _sid = require_session(session_id)?;
            let signed = handler
                .co_sign_receipt(receipt)
                .map_err(|e| BluefieldError::ProtocolError(e.to_string()))?;
            Ok(ProtocolMessage::ReceiptCoSigned { receipt: signed })
        }

        // ── Phase 6: Close ────────────────────────────────────────────────
        ProtocolMessage::SessionClose { session_id: sid } => {
            let _ = handler.handle_close(&sid);
            Ok(ProtocolMessage::SessionClosed)
        }

        // ── Streaming (Phase 4 extension) ─────────────────────────────────
        ProtocolMessage::StreamingMessage { id, ref content } => {
            let sid = require_session(session_id)?;
            match handler.handle_stream_message(&sid, &id, content) {
                Ok(Some(reply_content)) => Ok(ProtocolMessage::StreamingMessage {
                    id: uuid::Uuid::new_v4().to_string(),
                    content: reply_content,
                }),
                Ok(None) => Ok(ProtocolMessage::StreamingAck { id }),
                Err(e) => Ok(ProtocolMessage::Error {
                    code: "STREAM_ERROR".into(),
                    message: e.to_string(),
                }),
            }
        }

        other => Err(BluefieldError::ProtocolError(format!(
            "unexpected message in server: {}",
            other.message_type()
        ))),
    }
}

fn require_session(session_id: &Option<String>) -> Result<String, BluefieldError> {
    session_id.clone().ok_or_else(|| {
        BluefieldError::ProtocolError("session not established — phase 1 not completed".into())
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pap_core::{receipt::TransactionReceipt, session::CapabilityToken};
    use pap_transport::TransportError;

    struct PassHandler;

    impl AgentHandler for PassHandler {
        fn handle_token(&self, _: CapabilityToken) -> Result<(String, String), TransportError> {
            Ok(("s-pass".into(), "did:key:zPass".into()))
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
            Ok(serde_json::json!({"@type": "RdmaResult", "ok": true}))
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

    fn handler() -> Arc<PassHandler> {
        Arc::new(PassHandler)
    }

    fn make_token() -> CapabilityToken {
        CapabilityToken::mint(
            "did:key:zTarget".into(),
            "https://schema.org/SearchAction".into(),
            "did:key:zIssuer".into(),
            chrono::Utc::now() + chrono::TimeDelta::hours(1),
        )
    }

    #[test]
    fn phase1_token_accepted() {
        let h = handler();
        let mut sid = None;
        let resp = dispatch(
            &h,
            &mut sid,
            ProtocolMessage::TokenPresentation {
                token: make_token(),
            },
        )
        .unwrap();
        assert!(matches!(resp, ProtocolMessage::TokenAccepted { .. }));
        assert_eq!(sid.as_deref(), Some("s-pass"));
    }

    #[test]
    fn phase1_rejection_returned() {
        struct RejectHandler;
        impl AgentHandler for RejectHandler {
            fn handle_token(&self, _: CapabilityToken) -> Result<(String, String), TransportError> {
                Err(TransportError::HandlerError("forbidden".into()))
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

        let h = Arc::new(RejectHandler);
        let mut sid = None;
        let resp = dispatch(
            &h,
            &mut sid,
            ProtocolMessage::TokenPresentation {
                token: make_token(),
            },
        )
        .unwrap();
        assert!(matches!(resp, ProtocolMessage::TokenRejected { .. }));
        assert!(sid.is_none()); // no session established on rejection
    }

    #[test]
    fn phase2_requires_established_session() {
        let h = handler();
        let mut sid: Option<String> = None; // no session yet
        let resp = dispatch(
            &h,
            &mut sid,
            ProtocolMessage::SessionDidExchange {
                initiator_session_did: "did:key:zX".into(),
            },
        );
        assert!(resp.is_err());
    }

    #[test]
    fn phase5_requires_established_session() {
        let h = handler();
        let mut sid: Option<String> = None; // no session yet
        let receipt = TransactionReceipt {
            session_id: "s-orphan".into(),
            action: "https://schema.org/SearchAction".into(),
            initiating_agent_did: "did:key:zInit".into(),
            receiving_agent_did: "did:key:zPass".into(),
            disclosed_by_initiator: vec![],
            disclosed_by_receiver: vec![],
            executed: "ok".into(),
            returned: "ok".into(),
            payment_proof_commitment: None,
            timestamp: chrono::Utc::now(),
            signatures: vec![],
            attestations: vec![],
        };
        let resp = dispatch(&h, &mut sid, ProtocolMessage::ReceiptForCoSign { receipt });
        assert!(resp.is_err());
    }

    #[test]
    fn phase6_close_returns_session_closed() {
        let h = handler();
        let mut sid = Some("s-close".to_string());
        let resp = dispatch(
            &h,
            &mut sid,
            ProtocolMessage::SessionClose {
                session_id: "s-close".into(),
            },
        )
        .unwrap();
        assert!(matches!(resp, ProtocolMessage::SessionClosed));
    }

    #[tokio::test]
    async fn handle_channel_full_loop() {
        use crate::channel::MockChannel;
        use crate::client::BluefieldClient;

        let (client_chan, server_chan) = MockChannel::pair();
        let h = handler();

        // Run the server loop in the background
        tokio::spawn(async move {
            handle_channel(h, server_chan).await.unwrap();
        });

        let mut client = BluefieldClient::new(client_chan);

        // Phase 1
        let r1 = client.present_token(make_token()).await.unwrap();
        let session_id = match r1 {
            ProtocolMessage::TokenAccepted { session_id, .. } => session_id,
            x => panic!("{x:?}"),
        };

        // Phase 2
        client.exchange_did("did:key:zInit".into()).await.unwrap();

        // Phase 3
        client.send_disclosures(vec![]).await.unwrap();

        // Phase 4
        let r4 = client.request_execution().await.unwrap();
        match r4 {
            ProtocolMessage::ExecutionResult { result } => {
                assert_eq!(result["ok"], true);
            }
            x => panic!("{x:?}"),
        }

        // Phase 5 — minimal receipt
        let receipt = TransactionReceipt {
            session_id: session_id.clone(),
            action: "https://schema.org/SearchAction".into(),
            initiating_agent_did: "did:key:zInit".into(),
            receiving_agent_did: "did:key:zPass".into(),
            disclosed_by_initiator: vec![],
            disclosed_by_receiver: vec![],
            executed: "ok".into(),
            returned: "ok".into(),
            payment_proof_commitment: None,
            timestamp: chrono::Utc::now(),
            signatures: vec![],
            attestations: vec![],
        };
        let r5 = client.exchange_receipt(receipt).await.unwrap();
        assert!(matches!(r5, ProtocolMessage::ReceiptCoSigned { .. }));

        // Phase 6
        let r6 = client.close_session(session_id).await.unwrap();
        assert!(matches!(r6, ProtocolMessage::SessionClosed));
    }
}
