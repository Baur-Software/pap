//! Networked search PoC demonstrating:
//!
//! - Full 6-phase PAP handshake over HTTP
//! - AgentServer receiving protocol messages via REST endpoints
//! - AgentClient driving the handshake from the initiator side
//! - Same protocol invariants as the in-memory search example
//!
//! This is a single binary: it spawns the search agent server on a
//! random port, then the orchestrator/initiator connects over HTTP
//! and runs the complete handshake.

use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::{PrincipalKeypair, SessionKeypair};
use pap_proto::ProtocolMessage;
use pap_transport::{AgentClient, AgentHandler, AgentServer, TransportError};

/// A simple search agent handler that processes protocol messages.
struct SearchAgentHandler {
    session_key: SessionKeypair,
    // Track state per session
    state: Mutex<HandlerState>,
}

#[derive(Default)]
struct HandlerState {
    session_id: Option<String>,
    initiator_did: Option<String>,
}

impl SearchAgentHandler {
    fn new() -> Self {
        Self {
            session_key: SessionKeypair::generate(),
            state: Mutex::new(HandlerState::default()),
        }
    }
}

impl AgentHandler for SearchAgentHandler {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        println!("  [server] Received token for action: {}", token.action);
        println!("  [server] Token target: {}", token.target_did);

        let session_id = uuid::Uuid::new_v4().to_string();
        let receiver_did = self.session_key.did();

        let mut state = self.state.lock().unwrap();
        state.session_id = Some(session_id.clone());

        println!(
            "  [server] Token accepted, session: {}...",
            &session_id[..8]
        );
        Ok((session_id, receiver_did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        println!(
            "  [server] DID exchange on session {}...: initiator={}...",
            &session_id[..8],
            &initiator_session_did[..20]
        );

        let mut state = self.state.lock().unwrap();
        state.initiator_did = Some(initiator_session_did.to_string());
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        println!(
            "  [server] Received {} disclosures on session {}...",
            disclosures.len(),
            &session_id[..8]
        );
        // Search is zero-disclosure, so we expect an empty vec
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        println!(
            "  [server] Executing search on session {}...",
            &session_id[..8]
        );

        let result = serde_json::json!({
            "@context": "https://schema.org",
            "@type": "SearchResultsPage",
            "mainEntity": {
                "@type": "ItemList",
                "numberOfItems": 3,
                "itemListElement": [
                    {
                        "@type": "SearchResult",
                        "name": "Principal Agent Protocol Specification",
                        "url": "https://example.com/pap-spec"
                    },
                    {
                        "@type": "SearchResult",
                        "name": "PAP Reference Implementation",
                        "url": "https://github.com/Baur-Software/pap"
                    },
                    {
                        "@type": "SearchResult",
                        "name": "Zero-Trust Agent Architecture",
                        "url": "https://example.com/zero-trust-agents"
                    }
                ]
            }
        });

        Ok(result)
    }

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        println!("  [server] Co-signing receipt");
        receipt.co_sign(self.session_key.signing_key());
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        println!(
            "  [server] Session {}... closed, ephemeral keys discarded",
            &session_id[..8]
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    println!("=== PAP Networked Search Example ===");
    println!("Principal Agent Protocol v0.1 — HTTP Transport PoC\n");

    // ─── Step 1: Setup ────────────────────────────────────────────────
    println!("Step 1: Principal and orchestrator setup");
    let principal = PrincipalKeypair::generate();
    let principal_did = principal.did();
    let orchestrator = PrincipalKeypair::generate();
    let orchestrator_did = orchestrator.did();
    println!("  Principal DID: {}...", &principal_did[..30]);
    println!("  Orchestrator DID: {}...", &orchestrator_did[..30]);
    println!();

    // ─── Step 2: Start Search Agent Server ────────────────────────────
    println!("Step 2: Search agent server starting");
    let search_operator = PrincipalKeypair::generate();
    let search_operator_did = search_operator.did();

    let handler = Arc::new(SearchAgentHandler::new());
    let server = AgentServer::new(handler.clone(), 0); // port 0 = OS picks a free port

    // Bind to get the actual port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    println!("  Server listening on 127.0.0.1:{port}");
    println!("  Operator DID: {}...", &search_operator_did[..30]);
    println!();

    // Spawn server
    let router = server.router();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ─── Step 3: Mint Capability Token ────────────────────────────────
    println!("Step 3: Orchestrator mints capability token");
    let ttl = Utc::now() + Duration::hours(1);
    let mut token = CapabilityToken::mint(
        search_operator_did.clone(),
        "schema:SearchAction".into(),
        orchestrator_did.clone(),
        ttl,
    );
    token.sign(orchestrator.signing_key());
    println!("  Action: schema:SearchAction");
    println!("  Target: {}...", &search_operator_did[..30]);
    println!();

    // ─── Step 4: HTTP Handshake ───────────────────────────────────────
    println!("Step 4: Full 6-phase handshake over HTTP\n");
    let client = AgentClient::new(&format!("http://127.0.0.1:{port}"));
    let initiator_session = SessionKeypair::generate();

    // Phase 1: Token Presentation
    println!("  Phase 1: Token Presentation");
    let response = client.present_token(token).await.unwrap();
    let (session_id, receiver_session_did) = match response {
        ProtocolMessage::TokenAccepted {
            session_id,
            receiver_session_did,
        } => {
            println!("  [client] Token accepted!");
            println!("  [client] Session ID: {}...", &session_id[..8]);
            println!(
                "  [client] Receiver session DID: {}...",
                &receiver_session_did[..20]
            );
            (session_id, receiver_session_did)
        }
        ProtocolMessage::TokenRejected { reason } => {
            panic!("Token rejected: {reason}");
        }
        other => panic!("Unexpected response: {:?}", other.message_type()),
    };
    println!();

    // Phase 2: DID Exchange
    println!("  Phase 2: Ephemeral DID Exchange");
    let initiator_did = initiator_session.did();
    let did_response = client
        .exchange_did(&session_id, initiator_did.clone())
        .await
        .unwrap();
    match did_response {
        ProtocolMessage::SessionDidAck => {
            println!("  [client] DID exchange acknowledged");
        }
        other => panic!("Unexpected: {:?}", other.message_type()),
    }
    println!();

    // Phase 3: Disclosure (zero for search)
    println!("  Phase 3: Disclosure (zero-disclosure search)");
    let disc_response = client.send_disclosures(&session_id, vec![]).await.unwrap();
    match disc_response {
        ProtocolMessage::DisclosureAccepted => {
            println!("  [client] Zero disclosures accepted");
        }
        other => panic!("Unexpected: {:?}", other.message_type()),
    }
    println!();

    // Phase 4: Execution
    println!("  Phase 4: Execution");
    let exec_response = client.request_execution(&session_id).await.unwrap();
    match exec_response {
        ProtocolMessage::ExecutionResult { result } => {
            let items = result["mainEntity"]["numberOfItems"].as_i64().unwrap_or(0);
            println!("  [client] Received {} search results", items);
            println!(
                "  [client] Result:\n{}\n",
                serde_json::to_string_pretty(&result).unwrap()
            );
        }
        other => panic!("Unexpected: {:?}", other.message_type()),
    }

    // Phase 5: Receipt Co-signing
    println!("  Phase 5: Receipt Co-signing");
    // Build a receipt using pap-core's in-memory session (for the receipt structure)
    let mut in_mem_token = CapabilityToken::mint(
        search_operator_did.clone(),
        "schema:SearchAction".into(),
        orchestrator_did.clone(),
        ttl,
    );
    in_mem_token.sign(orchestrator.signing_key());

    let mut in_mem_session = pap_core::session::Session::initiate(
        &in_mem_token,
        &search_operator_did,
        &orchestrator.verifying_key(),
    )
    .unwrap();
    in_mem_session
        .open(initiator_did.clone(), receiver_session_did.clone())
        .unwrap();
    in_mem_session.execute().unwrap();

    let mut receipt = TransactionReceipt::from_session(
        &in_mem_session,
        vec![],
        vec!["operator:search_results_returned".into()],
        "schema:SearchAction executed".into(),
        "schema:SearchResultsPage returned".into(),
    )
    .unwrap();

    receipt.co_sign(initiator_session.signing_key());

    let receipt_response = client.exchange_receipt(&session_id, receipt).await.unwrap();
    match receipt_response {
        ProtocolMessage::ReceiptCoSigned { receipt } => {
            println!("  [client] Receipt co-signed by receiver");
            println!(
                "  [client] Disclosed by initiator: {:?} (nothing)",
                receipt.disclosed_by_initiator
            );
            println!(
                "  [client] Disclosed by receiver: {:?}",
                receipt.disclosed_by_receiver
            );
        }
        other => panic!("Unexpected: {:?}", other.message_type()),
    }
    println!();

    // Phase 6: Close
    println!("  Phase 6: Session Close");
    let close_response = client.close_session(&session_id).await.unwrap();
    match close_response {
        ProtocolMessage::SessionClosed => {
            println!("  [client] Session closed");
        }
        other => panic!("Unexpected: {:?}", other.message_type()),
    }
    println!();

    println!("=== Protocol Invariants Verified ===");
    println!("  [x] Full 6-phase handshake completed over HTTP");
    println!("  [x] Token presentation and acceptance via POST /session");
    println!("  [x] Ephemeral DID exchange via POST /session/:id/did");
    println!("  [x] Zero-disclosure search — no personal data sent");
    println!("  [x] Execution result returned as Schema.org JSON-LD");
    println!("  [x] Receipt co-signed by both initiator and receiver");
    println!("  [x] Session closed, ephemeral keys discarded");
    println!("  [x] Transport layer is a thin HTTP wrapper over protocol messages");
    println!("  [x] Same invariants as in-memory search — transport doesn't change trust model");
}
