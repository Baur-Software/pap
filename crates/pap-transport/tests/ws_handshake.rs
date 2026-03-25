//! Integration test: full 6-phase PAP handshake over loopback WebSocket.
//!
//! Verifies that `WsAgentClient` and `WsAgentServer` correctly implement
//! the PAP session protocol with no TLS (loopback).

use std::sync::Arc;

use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;
use pap_transport::{AgentHandler, TransportError, WsAgentClient, WsAgentServer};

/// Minimal test handler that accepts any token and returns canned responses.
struct TestHandler;

impl AgentHandler for TestHandler {
    fn handle_token(&self, _token: CapabilityToken) -> Result<(String, String), TransportError> {
        Ok(("test-session-1".into(), "did:key:zReceiverSession".into()))
    }

    fn handle_did_exchange(
        &self,
        _session_id: &str,
        _initiator_did: &str,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn handle_disclosure(
        &self,
        _session_id: &str,
        _disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        Ok(())
    }

    fn execute(&self, _session_id: &str) -> Result<serde_json::Value, TransportError> {
        Ok(serde_json::json!({
            "@type": "schema:SearchResult",
            "name": "Test Flight",
            "status": "confirmed"
        }))
    }

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        receipt.signatures.push("receiver-cosig".into());
        Ok(receipt)
    }

    fn handle_close(&self, _session_id: &str) -> Result<(), TransportError> {
        Ok(())
    }
}

#[tokio::test]
async fn full_handshake_over_websocket() {
    // Bind to port 0 so the OS assigns a free port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler: Arc<dyn AgentHandler> = Arc::new(TestHandler);
    let server = WsAgentServer::new(handler, 0);

    // Spawn server on the pre-bound listener
    let server_handle = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    // Connect client
    let mut client = WsAgentClient::connect_plain(&format!("ws://127.0.0.1:{port}"))
        .await
        .unwrap();

    // ── Phase 1: Token presentation ──────────────────────────────
    let token = CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:SearchAction".into(),
        "did:key:zIssuer".into(),
        Utc::now() + Duration::hours(1),
    );
    let resp = client.present_token(token).await.unwrap();
    let session_id = match &resp {
        ProtocolMessage::TokenAccepted {
            session_id,
            receiver_session_did,
        } => {
            assert_eq!(receiver_session_did, "did:key:zReceiverSession");
            session_id.clone()
        }
        other => panic!("Expected TokenAccepted, got: {other:?}"),
    };

    // ── Phase 2: DID exchange ────────────────────────────────────
    let resp = client
        .exchange_did(&session_id, "did:key:zInitiatorSession".into())
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionDidAck),
        "Expected SessionDidAck, got: {resp:?}"
    );

    // ── Phase 3: Disclosure (zero-disclosure) ────────────────────
    let resp = client.send_disclosures(&session_id, vec![]).await.unwrap();
    assert!(
        matches!(resp, ProtocolMessage::DisclosureAccepted),
        "Expected DisclosureAccepted, got: {resp:?}"
    );

    // ── Phase 4: Execute ─────────────────────────────────────────
    let resp = client.request_execution(&session_id).await.unwrap();
    match &resp {
        ProtocolMessage::ExecutionResult { result } => {
            assert_eq!(result["@type"], "schema:SearchResult");
            assert_eq!(result["status"], "confirmed");
        }
        other => panic!("Expected ExecutionResult, got: {other:?}"),
    }

    // ── Phase 5: Receipt co-signing ──────────────────────────────
    let receipt = TransactionReceipt {
        session_id: session_id.clone(),
        action: "schema:SearchAction".into(),
        initiating_agent_did: "did:key:zInitiatorSession".into(),
        receiving_agent_did: "did:key:zReceiverSession".into(),
        disclosed_by_initiator: vec![],
        disclosed_by_receiver: vec!["operator:search_executed".into()],
        executed: "schema:SearchAction executed".into(),
        returned: "schema:SearchResult returned".into(),
        timestamp: Utc::now(),
        signatures: vec!["initiator-sig".into()],
    };
    let resp = client.exchange_receipt(&session_id, receipt).await.unwrap();
    match &resp {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            assert_eq!(receipt.signatures.len(), 2);
            assert_eq!(receipt.signatures[0], "initiator-sig");
            assert_eq!(receipt.signatures[1], "receiver-cosig");
        }
        other => panic!("Expected ReceiptCoSigned, got: {other:?}"),
    }

    // ── Phase 6: Close ───────────────────────────────────────────
    let resp = client.close_session(&session_id).await.unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionClosed),
        "Expected SessionClosed, got: {resp:?}"
    );

    server_handle.abort();
}

#[tokio::test]
async fn token_rejection_over_websocket() {
    /// Handler that rejects all tokens.
    struct RejectHandler;

    impl AgentHandler for RejectHandler {
        fn handle_token(
            &self,
            _token: CapabilityToken,
        ) -> Result<(String, String), TransportError> {
            Err(TransportError::HandlerError("token expired".into()))
        }

        fn handle_did_exchange(&self, _session_id: &str, _did: &str) -> Result<(), TransportError> {
            Ok(())
        }

        fn handle_disclosure(
            &self,
            _session_id: &str,
            _d: Vec<serde_json::Value>,
        ) -> Result<(), TransportError> {
            Ok(())
        }

        fn execute(&self, _session_id: &str) -> Result<serde_json::Value, TransportError> {
            Ok(serde_json::json!({}))
        }

        fn co_sign_receipt(
            &self,
            receipt: TransactionReceipt,
        ) -> Result<TransactionReceipt, TransportError> {
            Ok(receipt)
        }

        fn handle_close(&self, _session_id: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler: Arc<dyn AgentHandler> = Arc::new(RejectHandler);
    let server = WsAgentServer::new(handler, 0);

    let server_handle = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    let mut client = WsAgentClient::connect_plain(&format!("ws://127.0.0.1:{port}"))
        .await
        .unwrap();

    let token = CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:SearchAction".into(),
        "did:key:zIssuer".into(),
        Utc::now() + Duration::hours(1),
    );

    let resp = client.present_token(token).await.unwrap();
    match resp {
        ProtocolMessage::TokenRejected { reason } => {
            assert!(reason.contains("token expired"), "reason was: {reason}");
        }
        other => panic!("Expected TokenRejected, got: {other:?}"),
    }

    server_handle.abort();
}
