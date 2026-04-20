//! PAP agent initiator over a BlueField RDMA channel.
//!
//! [`BluefieldClient`] drives the six-phase PAP handshake over any
//! [`crate::channel::MessageChannel`] — real RDMA in production, in-memory
//! mock in tests.
//!
//! The API mirrors [`pap_transport::AgentClient`] but operates over RDMA
//! rather than HTTP.

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;

use crate::channel::MessageChannel;
use crate::error::BluefieldError;

// ── Client ────────────────────────────────────────────────────────────────────

/// Drives the six-phase PAP handshake as the initiating agent.
///
/// Generic over any [`MessageChannel`] implementation.  In production
/// construct with an [`crate::rdma::connection::RdmaConnection`]; in tests
/// use a [`crate::channel::MockChannel`].
pub struct BluefieldClient<C: MessageChannel> {
    channel: C,
}

impl<C: MessageChannel> BluefieldClient<C> {
    pub fn new(channel: C) -> Self {
        Self { channel }
    }

    // ── Phase 1: Token Presentation ──────────────────────────────────────

    /// Present a capability token to the receiving agent.
    ///
    /// Returns `TokenAccepted { session_id, receiver_session_did }` on
    /// success, or `TokenRejected { reason }` if the receiver declines.
    pub async fn present_token(
        &mut self,
        token: CapabilityToken,
    ) -> Result<ProtocolMessage, BluefieldError> {
        let msg = ProtocolMessage::TokenPresentation { token };
        self.channel.send_msg(&msg).await?;
        self.channel.recv_msg().await
    }

    // ── Phase 2: Ephemeral DID Exchange ──────────────────────────────────

    /// Send the initiator's ephemeral session DID.
    ///
    /// Returns `SessionDidAck` on success.
    pub async fn exchange_did(
        &mut self,
        initiator_session_did: String,
    ) -> Result<ProtocolMessage, BluefieldError> {
        let msg = ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        };
        self.channel.send_msg(&msg).await?;
        self.channel.recv_msg().await
    }

    // ── Phase 3: Disclosure ───────────────────────────────────────────────

    /// Offer selective disclosures (empty vec for zero-disclosure sessions).
    ///
    /// Returns `DisclosureAccepted` on success.
    pub async fn send_disclosures(
        &mut self,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<ProtocolMessage, BluefieldError> {
        let msg = ProtocolMessage::DisclosureOffer { disclosures };
        self.channel.send_msg(&msg).await?;
        self.channel.recv_msg().await
    }

    // ── Phase 4: Execution ────────────────────────────────────────────────

    /// Request execution of the delegated action.
    ///
    /// Returns `ExecutionResult { result }` containing the Schema.org JSON-LD
    /// result from the receiving agent.
    pub async fn request_execution(&mut self) -> Result<ProtocolMessage, BluefieldError> {
        // Phase 4 has no request payload — the receiver executes and replies.
        // We send an empty DisclosureAccepted as a trigger sentinel; the server
        // side recognises the empty execution slot and calls handler.execute().
        // Using SessionDidAck as a lightweight "ping" is idiomatic for PAP RDMA.
        let msg = ProtocolMessage::SessionDidAck; // trigger frame
        self.channel.send_msg(&msg).await?;
        self.channel.recv_msg().await
    }

    // ── Phase 5: Receipt Co-signing ───────────────────────────────────────

    /// Send a half-signed receipt for the receiver to co-sign.
    ///
    /// Returns `ReceiptCoSigned { receipt }`.
    pub async fn exchange_receipt(
        &mut self,
        receipt: TransactionReceipt,
    ) -> Result<ProtocolMessage, BluefieldError> {
        let msg = ProtocolMessage::ReceiptForCoSign { receipt };
        self.channel.send_msg(&msg).await?;
        self.channel.recv_msg().await
    }

    // ── Phase 6: Close ────────────────────────────────────────────────────

    /// Close the session.
    ///
    /// Returns `SessionClosed`.
    pub async fn close_session(
        &mut self,
        session_id: String,
    ) -> Result<ProtocolMessage, BluefieldError> {
        let msg = ProtocolMessage::SessionClose { session_id };
        self.channel.send_msg(&msg).await?;
        self.channel.recv_msg().await
    }
}

// ── Convenience constructors ──────────────────────────────────────────────────

#[cfg(feature = "rdma")]
impl BluefieldClient<crate::rdma::connection::RdmaConnection> {
    /// Connect to a [`crate::rdma::connection::RdmaBootstrapServer`] and
    /// return a client ready to drive the PAP handshake.
    ///
    /// # Arguments
    /// * `bootstrap_addr` — TCP address of the server's bootstrap port,
    ///   e.g. `"192.168.200.1:7777"`.
    /// * `dev` — the local BlueField [`crate::rdma::context::DeviceContext`].
    pub async fn connect_rdma(
        bootstrap_addr: &str,
        dev: std::sync::Arc<crate::rdma::context::DeviceContext>,
    ) -> Result<Self, BluefieldError> {
        let conn =
            crate::rdma::connection::RdmaBootstrapClient::connect(bootstrap_addr, dev).await?;
        Ok(Self::new(conn))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::MockChannel;
    use crate::server::handle_channel;
    use pap_core::{receipt::TransactionReceipt, session::CapabilityToken};
    use pap_transport::{AgentHandler, TransportError};
    use std::sync::{Arc, Mutex};

    // ── Minimal stub handler ──────────────────────────────────────────────

    struct EchoHandler {
        executions: Mutex<Vec<String>>,
    }

    impl EchoHandler {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                executions: Mutex::new(Vec::new()),
            })
        }
    }

    impl AgentHandler for EchoHandler {
        fn handle_token(
            &self,
            _token: CapabilityToken,
        ) -> Result<(String, String), TransportError> {
            Ok(("sess-echo".into(), "did:key:zEchoRdma".into()))
        }

        fn handle_did_exchange(&self, _sid: &str, _did: &str) -> Result<(), TransportError> {
            Ok(())
        }

        fn handle_disclosure(
            &self,
            _sid: &str,
            _disclosures: Vec<serde_json::Value>,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn execute(&self, sid: &str) -> Result<serde_json::Value, TransportError> {
            self.executions.lock().unwrap().push(sid.to_string());
            Ok(serde_json::json!({
                "@context": "https://schema.org",
                "@type": "SearchResultsPage",
                "transport": "rdma"
            }))
        }

        fn co_sign_receipt(
            &self,
            r: TransactionReceipt,
        ) -> Result<TransactionReceipt, TransportError> {
            Ok(r)
        }

        fn handle_close(&self, _sid: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn make_token() -> CapabilityToken {
        CapabilityToken::mint(
            "did:key:zReceiverAgent".into(),
            "https://schema.org/SearchAction".into(),
            "did:key:zTestIssuer".into(),
            chrono::Utc::now() + chrono::TimeDelta::hours(1),
        )
    }

    fn make_receipt(session_id: &str) -> TransactionReceipt {
        TransactionReceipt {
            session_id: session_id.to_string(),
            action: "https://schema.org/SearchAction".into(),
            initiating_agent_did: "did:key:zInitiator".into(),
            receiving_agent_did: "did:key:zReceiver".into(),
            disclosed_by_initiator: vec![],
            disclosed_by_receiver: vec![],
            executed: "search performed".into(),
            returned: "results returned".into(),
            payment_proof_commitment: None,
            disclosure_hash: None,
            timestamp: chrono::Utc::now(),
            signatures: vec![],
            attestations: vec![],
        }
    }

    // ── Full handshake over mock channel ──────────────────────────────────

    #[tokio::test]
    async fn full_six_phase_handshake_mock() {
        let (client_chan, server_chan) = MockChannel::pair();
        let handler = EchoHandler::new();
        let handler_clone = Arc::clone(&handler);

        // Spawn the server side
        let server_task = tokio::spawn(async move {
            handle_channel(handler_clone, server_chan).await.unwrap();
        });

        // Drive the client
        let mut client = BluefieldClient::new(client_chan);

        // Phase 1
        let resp = client.present_token(make_token()).await.unwrap();
        let session_id = match resp {
            ProtocolMessage::TokenAccepted { session_id, .. } => session_id,
            other => panic!("phase 1: expected TokenAccepted, got {other:?}"),
        };

        // Phase 2
        let resp = client
            .exchange_did("did:key:zInitiatorEphemeral".into())
            .await
            .unwrap();
        assert!(
            matches!(resp, ProtocolMessage::SessionDidAck),
            "phase 2: {resp:?}"
        );

        // Phase 3 — zero disclosure
        let resp = client.send_disclosures(vec![]).await.unwrap();
        assert!(
            matches!(resp, ProtocolMessage::DisclosureAccepted),
            "phase 3: {resp:?}"
        );

        // Phase 4
        let resp = client.request_execution().await.unwrap();
        match resp {
            ProtocolMessage::ExecutionResult { result } => {
                assert_eq!(result["transport"], "rdma");
            }
            other => panic!("phase 4: expected ExecutionResult, got {other:?}"),
        }

        // Phase 5
        let receipt = make_receipt(&session_id);
        let resp = client.exchange_receipt(receipt).await.unwrap();
        assert!(
            matches!(resp, ProtocolMessage::ReceiptCoSigned { .. }),
            "phase 5: {resp:?}"
        );

        // Phase 6
        let resp = client.close_session(session_id).await.unwrap();
        assert!(
            matches!(resp, ProtocolMessage::SessionClosed),
            "phase 6: {resp:?}"
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn token_rejection_propagated() {
        struct RejectHandler;
        impl AgentHandler for RejectHandler {
            fn handle_token(&self, _: CapabilityToken) -> Result<(String, String), TransportError> {
                Err(TransportError::HandlerError("bad token".into()))
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

        let (client_chan, server_chan) = MockChannel::pair();
        let handler = Arc::new(RejectHandler);

        tokio::spawn(async move {
            let _ = handle_channel(handler, server_chan).await;
        });

        let mut client = BluefieldClient::new(client_chan);
        let resp = client.present_token(make_token()).await.unwrap();
        assert!(
            matches!(resp, ProtocolMessage::TokenRejected { .. }),
            "expected TokenRejected, got {resp:?}"
        );
    }
}
