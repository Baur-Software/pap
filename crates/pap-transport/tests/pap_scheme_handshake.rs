//! E2E tests: PAP handshakes over HTTP and WebSocket transports.
//!
//! Tests the full 6-phase PAP protocol handshake using plain loopback
//! connections (no TLS). In production, `reqwest`/`tokio-tungstenite`
//! perform a TLS handshake first, but the PAP protocol phases are identical.
//!
//! pap+https:// and pap+wss:// URI resolution is tested in papillon-shared's
//! own test suite (crates/papillon-shared/src/pap_uri.rs).

use std::sync::Arc;

use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;
use pap_transport::{
    AgentClient, AgentHandler, AgentServer, TransportError, WsAgentClient, WsAgentServer,
};

// ── Shared test handler ──────────────────────────────────────────────────────

/// Minimal handler: accepts every token, echoes a canned result, co-signs receipts.
struct TestHandler;

impl AgentHandler for TestHandler {
    fn handle_token(&self, _token: CapabilityToken) -> Result<(String, String), TransportError> {
        Ok(("sess-e2e-1".into(), "did:key:zReceiverSession".into()))
    }

    fn handle_did_exchange(&self, _session_id: &str, _did: &str) -> Result<(), TransportError> {
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
            "name": "PAP scheme test result",
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

// ── E2E handshake tests ──────────────────────────────────────────────────────
// URI scheme resolution (pap+https:// → https://, pap+wss:// → wss://)
// is tested in crates/papillon-shared/src/pap_uri.rs.

/// Full 6-phase PAP handshake via HTTP transport.
/// Simulates what happens after pap+https:// is resolved to an https:// endpoint
/// and the loopback URL is derived from it (without TLS for test speed).
#[tokio::test]
async fn pap_https_scheme_full_six_phase_handshake() {
    // ── 1. Bind server on an OS-assigned port ────────────────────────────
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler: Arc<dyn AgentHandler> = Arc::new(TestHandler);
    let server = AgentServer::new(handler, 0);
    let router = server.router();

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // ── 2. Build loopback endpoint (pap+https:// resolves to https://,
    //        which for loopback testing uses http:// to avoid TLS setup) ────
    let endpoint = format!("http://127.0.0.1:{}", port);
    let client = AgentClient::new(&endpoint);

    // Mandate TTL used for all phase checks (valid for 1 hour)
    let mandate_expires_at = Utc::now() + Duration::hours(1);

    // ── Phase 1: Token presentation ──────────────────────────────────────
    let token = CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:BuyAction".into(),
        "did:key:zIssuer".into(),
        mandate_expires_at,
    );
    let resp = client.present_token(token).await.unwrap();
    let session_id = match &resp {
        ProtocolMessage::TokenAccepted {
            session_id,
            receiver_session_did,
            ..
        } => {
            assert_eq!(receiver_session_did, "did:key:zReceiverSession");
            session_id.clone()
        }
        other => panic!("Phase 1 — expected TokenAccepted, got: {other:?}"),
    };

    // ── Phase 2: DID exchange ────────────────────────────────────────────
    let resp = client
        .exchange_did(
            &session_id,
            "did:key:zInitiatorSession".into(),
            mandate_expires_at,
        )
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionDidAck),
        "Phase 2 — expected SessionDidAck, got: {resp:?}"
    );

    // ── Phase 3: Zero-disclosure offer ───────────────────────────────────
    let resp = client
        .send_disclosures(&session_id, vec![], mandate_expires_at)
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::DisclosureAccepted),
        "Phase 3 — expected DisclosureAccepted, got: {resp:?}"
    );

    // ── Phase 4: Execute ─────────────────────────────────────────────────
    let resp = client
        .request_execution(&session_id, mandate_expires_at)
        .await
        .unwrap();
    match &resp {
        ProtocolMessage::ExecutionResult { result } => {
            assert_eq!(result["@type"], "schema:SearchResult");
            assert_eq!(result["status"], "confirmed");
        }
        other => panic!("Phase 4 — expected ExecutionResult, got: {other:?}"),
    }

    // ── Phase 5: Receipt co-signing ──────────────────────────────────────
    let receipt = TransactionReceipt {
        session_id: session_id.clone(),
        action: "schema:BuyAction".into(),
        initiating_agent_did: "did:key:zInitiatorSession".into(),
        receiving_agent_did: "did:key:zReceiverSession".into(),
        disclosed_by_initiator: vec![],
        disclosed_by_receiver: vec!["operator:buy_executed".into()],
        executed: "schema:BuyAction executed".into(),
        returned: "schema:SearchResult returned".into(),
        payment_proof_commitment: None,
        disclosure_hash: None,
        timestamp: Utc::now(),
        signatures: vec!["initiator-sig".into()],
        attestations: vec![],
    };
    let resp = client
        .exchange_receipt(&session_id, receipt, mandate_expires_at)
        .await
        .unwrap();
    match &resp {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            assert_eq!(receipt.signatures.len(), 2, "both parties must co-sign");
            assert_eq!(receipt.signatures[0], "initiator-sig");
            assert_eq!(receipt.signatures[1], "receiver-cosig");
        }
        other => panic!("Phase 5 — expected ReceiptCoSigned, got: {other:?}"),
    }

    // ── Phase 6: Close ───────────────────────────────────────────────────
    let resp = client
        .close_session(&session_id, mandate_expires_at)
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionClosed),
        "Phase 6 — expected SessionClosed, got: {resp:?}"
    );

    server_handle.abort();
}

/// `pap+wss://` — full 6-phase handshake via WebSocket transport.
#[tokio::test]
async fn pap_wss_scheme_full_six_phase_handshake() {
    // ── 1. Bind WS server on an OS-assigned port ─────────────────────────
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler: Arc<dyn AgentHandler> = Arc::new(TestHandler);
    let server = WsAgentServer::new(handler, 0);

    let server_handle = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });

    // ── 2. Build loopback endpoint (pap+wss:// resolves to wss://,
    //        which for loopback testing uses ws:// to avoid TLS setup) ──────
    let endpoint = format!("ws://127.0.0.1:{}", port);
    let mut client = WsAgentClient::connect_plain(&endpoint).await.unwrap();

    // Mandate TTL used for all phase checks (valid for 1 hour)
    let mandate_expires_at = Utc::now() + Duration::hours(1);

    // ── Phase 1: Token presentation ──────────────────────────────────────
    let token = CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:ListenAction".into(),
        "did:key:zIssuer".into(),
        mandate_expires_at,
    );
    let resp = client.present_token(token).await.unwrap();
    let session_id = match &resp {
        ProtocolMessage::TokenAccepted {
            session_id,
            receiver_session_did,
            ..
        } => {
            assert_eq!(receiver_session_did, "did:key:zReceiverSession");
            session_id.clone()
        }
        other => panic!("Phase 1 — expected TokenAccepted, got: {other:?}"),
    };

    // ── Phase 2: DID exchange ────────────────────────────────────────────
    let resp = client
        .exchange_did(
            &session_id,
            "did:key:zInitiatorSession".into(),
            mandate_expires_at,
        )
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionDidAck),
        "Phase 2 — expected SessionDidAck, got: {resp:?}"
    );

    // ── Phase 3: Zero-disclosure offer ───────────────────────────────────
    let resp = client
        .send_disclosures(&session_id, vec![], mandate_expires_at)
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::DisclosureAccepted),
        "Phase 3 — expected DisclosureAccepted, got: {resp:?}"
    );

    // ── Phase 4: Execute ─────────────────────────────────────────────────
    let resp = client
        .request_execution(&session_id, mandate_expires_at)
        .await
        .unwrap();
    match &resp {
        ProtocolMessage::ExecutionResult { result } => {
            assert_eq!(result["@type"], "schema:SearchResult");
            assert_eq!(result["status"], "confirmed");
        }
        other => panic!("Phase 4 — expected ExecutionResult, got: {other:?}"),
    }

    // ── Phase 5: Receipt co-signing ──────────────────────────────────────
    let receipt = TransactionReceipt {
        session_id: session_id.clone(),
        action: "schema:ListenAction".into(),
        initiating_agent_did: "did:key:zInitiatorSession".into(),
        receiving_agent_did: "did:key:zReceiverSession".into(),
        disclosed_by_initiator: vec![],
        disclosed_by_receiver: vec!["operator:listen_executed".into()],
        executed: "schema:ListenAction executed".into(),
        returned: "schema:SearchResult returned".into(),
        payment_proof_commitment: None,
        disclosure_hash: None,
        timestamp: Utc::now(),
        signatures: vec!["initiator-sig".into()],
        attestations: vec![],
    };
    let resp = client
        .exchange_receipt(&session_id, receipt, mandate_expires_at)
        .await
        .unwrap();
    match &resp {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            assert_eq!(receipt.signatures.len(), 2, "both parties must co-sign");
            assert_eq!(receipt.signatures[0], "initiator-sig");
            assert_eq!(receipt.signatures[1], "receiver-cosig");
        }
        other => panic!("Phase 5 — expected ReceiptCoSigned, got: {other:?}"),
    }

    // ── Phase 6: Close ───────────────────────────────────────────────────
    let resp = client
        .close_session(&session_id, mandate_expires_at)
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionClosed),
        "Phase 6 — expected SessionClosed, got: {resp:?}"
    );

    server_handle.abort();
}

/// Verify that an already-expired mandate TTL causes phase 2 onwards to fail
/// with `TransportError::MandateExpired` (spec §5.5).
#[tokio::test]
async fn expired_mandate_ttl_blocks_phase_transitions_http() {
    // ── Bind a real server so the client has somewhere to connect ────────
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handler: Arc<dyn AgentHandler> = Arc::new(TestHandler);
    let server = AgentServer::new(handler, 0);
    let router = server.router();

    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let endpoint = format!("http://127.0.0.1:{}", port);
    let client = AgentClient::new(&endpoint);

    // Already-expired TTL (1 second in the past)
    let expired_ttl = Utc::now() - Duration::seconds(1);

    // Phase 2 must fail immediately without making a network request
    let result = client
        .exchange_did("any-session", "did:key:zInit".into(), expired_ttl)
        .await;
    assert!(
        matches!(result, Err(TransportError::MandateExpired)),
        "Phase 2 with expired TTL must return MandateExpired, got: {result:?}"
    );

    // Phase 3 must also fail
    let result = client
        .send_disclosures("any-session", vec![], expired_ttl)
        .await;
    assert!(
        matches!(result, Err(TransportError::MandateExpired)),
        "Phase 3 with expired TTL must return MandateExpired, got: {result:?}"
    );

    // Phase 4 must also fail
    let result = client.request_execution("any-session", expired_ttl).await;
    assert!(
        matches!(result, Err(TransportError::MandateExpired)),
        "Phase 4 with expired TTL must return MandateExpired, got: {result:?}"
    );

    server_handle.abort();
}
