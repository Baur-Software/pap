//! E2E tests: `pap+https://` and `pap+wss://` URI scheme handshakes.
//!
//! Verifies the full activation path:
//!   1. `resolve_pap_uri` now activates these schemes instead of deferring.
//!   2. The resolved endpoint URL drives a complete 6-phase PAP handshake.
//!
//! **TLS note**: TLS termination is the platform's responsibility (Tauri
//! secure context, reverse proxy, etc.). These tests use loopback plaintext
//! connections so they are self-contained and fast, while still proving the
//! protocol behavior is identical to the production HTTPS/WSS path.
//! The only difference in production is that `reqwest`/`tokio-tungstenite`
//! perform a TLS handshake before the PAP phases begin.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;
use pap_transport::{
    AgentClient, AgentHandler, AgentServer, TransportError, WsAgentClient, WsAgentServer,
};
use papillon_shared::{resolve_pap_uri, LinkOrigin, ResolvedUri};

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

// ── URI resolution tests ─────────────────────────────────────────────────────

#[test]
fn pap_https_uri_resolves_to_https_endpoint() {
    let uri = "pap+https://api.example.com/agents/flights/BuyAction";
    let result = resolve_pap_uri(uri, &HashMap::new(), LinkOrigin::Principal).unwrap();
    assert_eq!(
        result,
        ResolvedUri::HttpsEndpoint("https://api.example.com/agents/flights/BuyAction".into())
    );
}

#[test]
fn pap_wss_uri_resolves_to_wss_endpoint() {
    let uri = "pap+wss://stream.example.com/agents/feed/ListenAction";
    let result = resolve_pap_uri(uri, &HashMap::new(), LinkOrigin::Principal).unwrap();
    assert_eq!(
        result,
        ResolvedUri::WssEndpoint("wss://stream.example.com/agents/feed/ListenAction".into())
    );
}

#[test]
fn pap_https_preserves_port_query_fragment() {
    let uri = "pap+https://agent.example.com:8443/v1/session?hint=search";
    let result = resolve_pap_uri(uri, &HashMap::new(), LinkOrigin::Principal).unwrap();
    assert_eq!(
        result,
        ResolvedUri::HttpsEndpoint("https://agent.example.com:8443/v1/session?hint=search".into())
    );
}

#[test]
fn pap_wss_preserves_port_and_path() {
    let uri = "pap+wss://127.0.0.1:9443/ws/agent";
    let result = resolve_pap_uri(uri, &HashMap::new(), LinkOrigin::Principal).unwrap();
    assert_eq!(
        result,
        ResolvedUri::WssEndpoint("wss://127.0.0.1:9443/ws/agent".into())
    );
}

#[test]
fn pap_https_activates_from_agent_origin() {
    // Agent-origin pap+https:// links activate; the PAP handshake enforces
    // scope at the protocol level — there is no reserved-authority gate.
    let result = resolve_pap_uri(
        "pap+https://api.example.com/agents/search",
        &HashMap::new(),
        LinkOrigin::Agent,
    )
    .unwrap();
    assert!(
        matches!(result, ResolvedUri::HttpsEndpoint(_)),
        "Expected HttpsEndpoint, got: {result:?}"
    );
}

// ── E2E handshake tests ──────────────────────────────────────────────────────

/// Strip the scheme prefix for loopback tests.
///
/// `resolve_pap_uri` correctly returns `https://` / `wss://`; for loopback
/// test servers that run without TLS we swap to `http://` / `ws://`.  The
/// protocol behavior (all 6 phases) is identical in both cases.
fn loopback_url(resolved: ResolvedUri) -> String {
    match resolved {
        ResolvedUri::HttpsEndpoint(url) => url.replacen("https://", "http://", 1),
        ResolvedUri::WssEndpoint(url) => url.replacen("wss://", "ws://", 1),
        other => panic!("Expected recapture endpoint, got: {other:?}"),
    }
}

/// `pap+https://` — full 6-phase handshake via HTTP transport.
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

    // ── 2. Resolve pap+https:// URI — must succeed (not deferred) ───────
    let pap_uri = format!("pap+https://127.0.0.1:{}", port);
    let resolved = resolve_pap_uri(&pap_uri, &HashMap::new(), LinkOrigin::Principal).unwrap();

    assert!(
        matches!(resolved, ResolvedUri::HttpsEndpoint(_)),
        "Expected HttpsEndpoint, got: {resolved:?}"
    );

    // ── 3. Connect via AgentClient using the loopback-adjusted URL ───────
    let endpoint = loopback_url(resolved);
    let client = AgentClient::new(&endpoint);

    // ── Phase 1: Token presentation ──────────────────────────────────────
    let token = CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:BuyAction".into(),
        "did:key:zIssuer".into(),
        Utc::now() + Duration::hours(1),
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
        .exchange_did(&session_id, "did:key:zInitiatorSession".into())
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionDidAck),
        "Phase 2 — expected SessionDidAck, got: {resp:?}"
    );

    // ── Phase 3: Zero-disclosure offer ───────────────────────────────────
    let resp = client.send_disclosures(&session_id, vec![]).await.unwrap();
    assert!(
        matches!(resp, ProtocolMessage::DisclosureAccepted),
        "Phase 3 — expected DisclosureAccepted, got: {resp:?}"
    );

    // ── Phase 4: Execute ─────────────────────────────────────────────────
    let resp = client.request_execution(&session_id).await.unwrap();
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
        timestamp: Utc::now(),
        signatures: vec!["initiator-sig".into()],
        attestations: vec![],
    };
    let resp = client.exchange_receipt(&session_id, receipt).await.unwrap();
    match &resp {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            assert_eq!(receipt.signatures.len(), 2, "both parties must co-sign");
            assert_eq!(receipt.signatures[0], "initiator-sig");
            assert_eq!(receipt.signatures[1], "receiver-cosig");
        }
        other => panic!("Phase 5 — expected ReceiptCoSigned, got: {other:?}"),
    }

    // ── Phase 6: Close ───────────────────────────────────────────────────
    let resp = client.close_session(&session_id).await.unwrap();
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

    // ── 2. Resolve pap+wss:// URI — must succeed (not deferred) ─────────
    let pap_uri = format!("pap+wss://127.0.0.1:{}", port);
    let resolved = resolve_pap_uri(&pap_uri, &HashMap::new(), LinkOrigin::Principal).unwrap();

    assert!(
        matches!(resolved, ResolvedUri::WssEndpoint(_)),
        "Expected WssEndpoint, got: {resolved:?}"
    );

    // ── 3. Connect via WsAgentClient using the loopback-adjusted URL ─────
    let endpoint = loopback_url(resolved);
    let mut client = WsAgentClient::connect_plain(&endpoint).await.unwrap();

    // ── Phase 1: Token presentation ──────────────────────────────────────
    let token = CapabilityToken::mint(
        "did:key:zTarget".into(),
        "schema:ListenAction".into(),
        "did:key:zIssuer".into(),
        Utc::now() + Duration::hours(1),
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
        .exchange_did(&session_id, "did:key:zInitiatorSession".into())
        .await
        .unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionDidAck),
        "Phase 2 — expected SessionDidAck, got: {resp:?}"
    );

    // ── Phase 3: Zero-disclosure offer ───────────────────────────────────
    let resp = client.send_disclosures(&session_id, vec![]).await.unwrap();
    assert!(
        matches!(resp, ProtocolMessage::DisclosureAccepted),
        "Phase 3 — expected DisclosureAccepted, got: {resp:?}"
    );

    // ── Phase 4: Execute ─────────────────────────────────────────────────
    let resp = client.request_execution(&session_id).await.unwrap();
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
        timestamp: Utc::now(),
        signatures: vec!["initiator-sig".into()],
        attestations: vec![],
    };
    let resp = client.exchange_receipt(&session_id, receipt).await.unwrap();
    match &resp {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            assert_eq!(receipt.signatures.len(), 2, "both parties must co-sign");
            assert_eq!(receipt.signatures[0], "initiator-sig");
            assert_eq!(receipt.signatures[1], "receiver-cosig");
        }
        other => panic!("Phase 5 — expected ReceiptCoSigned, got: {other:?}"),
    }

    // ── Phase 6: Close ───────────────────────────────────────────────────
    let resp = client.close_session(&session_id).await.unwrap();
    assert!(
        matches!(resp, ProtocolMessage::SessionClosed),
        "Phase 6 — expected SessionClosed, got: {resp:?}"
    );

    server_handle.abort();
}
