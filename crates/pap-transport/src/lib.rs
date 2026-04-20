pub mod client;
pub mod endpoint;
pub mod error;
pub mod handler;
pub mod ohttp;
pub mod ohttp_client;
pub mod remote;
pub mod server;
pub mod ws_client;
pub mod ws_remote;
pub mod ws_server;

pub(crate) mod limited_read;
pub(crate) mod ws_common;

pub use client::AgentClient;
pub use endpoint::EndpointRegistry;
pub use error::TransportError;
pub use handler::AgentHandler;
pub use ohttp::{
    fetch_key_config, OhttpConfig, OhttpEncryptor, OhttpKeyConfig, OhttpKeyPair,
    OhttpResponseDecryptCtx, OhttpResponseEncryptCtx, OhttpServerDecryptor,
};
pub use ohttp_client::OhttpClient;
pub use remote::RemoteAgentHandler;
pub use server::AgentServer;
pub use ws_client::WsAgentClient;
pub use ws_remote::WsRemoteAgentHandler;
pub use ws_server::WsAgentServer;

#[cfg(test)]
mod tests {
    use super::*;
    use pap_proto::ProtocolMessage;

    #[test]
    fn endpoint_registry_register_and_resolve() {
        let mut registry = EndpointRegistry::new();
        registry.register("did:key:zABC", "http://127.0.0.1:8080");
        registry.register("did:key:zDEF", "http://127.0.0.1:8081");

        assert_eq!(
            registry.resolve("did:key:zABC"),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            registry.resolve("did:key:zDEF"),
            Some("http://127.0.0.1:8081")
        );
        assert_eq!(registry.resolve("did:key:zMissing"), None);
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn protocol_message_json_type_tag() {
        // Verify the serde tag shows up correctly for HTTP transport
        let msg = ProtocolMessage::TokenAccepted {
            session_id: "s1".into(),
            receiver_session_did: "did:key:z123".into(),
            attestation: None,
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "TokenAccepted");
    }

    #[test]
    fn client_construction() {
        // Just verify it doesn't panic
        let _client = AgentClient::new("http://127.0.0.1:9000");
        let _client = AgentClient::new("http://127.0.0.1:9000/");
    }

    // ── run_full_handshake integration tests ──────────────────────────────────

    /// Minimal in-process handler for testing. Accepts all tokens, executes a
    /// canned search result, and co-signs receipts without signature verification.
    struct TestHandler;

    impl AgentHandler for TestHandler {
        fn handle_token(
            &self,
            _token: pap_core::session::CapabilityToken,
        ) -> Result<(String, String), TransportError> {
            Ok((
                "test-session-id".to_string(),
                "did:key:zTestReceiver".to_string(),
            ))
        }

        fn handle_did_exchange(
            &self,
            _session_id: &str,
            _initiator_session_did: &str,
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
                "@context": "https://schema.org",
                "@type": "SearchResultsPage",
                "name": "test result"
            }))
        }

        fn co_sign_receipt(
            &self,
            mut receipt: pap_core::receipt::TransactionReceipt,
        ) -> Result<pap_core::receipt::TransactionReceipt, TransportError> {
            // In a real handler this would sign with the receiver's session key.
            // For the test we push a placeholder signature so the receipt has 2 sigs.
            use base64::Engine;
            receipt
                .signatures
                .push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]));
            Ok(receipt)
        }

        fn handle_close(&self, _session_id: &str) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// Spin up a real `AgentServer` on a random port, run `run_full_handshake()`
    /// against it, and verify that:
    ///
    /// 1. The function returns `Ok` (all 6 phases complete without error).
    /// 2. The returned receipt carries the co-signed copy (Phase 5 was executed).
    /// 3. The returned result contains the expected Schema.org payload (Phase 4).
    #[tokio::test]
    async fn run_full_handshake_end_to_end() {
        use std::sync::Arc;

        use chrono::{Duration, Utc};
        use pap_core::receipt::TransactionReceipt;
        use pap_core::session::CapabilityToken;

        // Spin up the server on an OS-assigned port.
        let handler = Arc::new(TestHandler);
        let server = AgentServer::new(handler, 0);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        // Give the server a moment to start accepting connections.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Build client.
        let client = AgentClient::new(&format!("http://127.0.0.1:{port}"));

        // Mint a capability token (no real signature verification in TestHandler).
        let ttl = Utc::now() + Duration::hours(1);
        let token = CapabilityToken::mint(
            "did:key:zTestReceiver".into(),
            "schema:SearchAction".into(),
            "did:key:zTestIssuer".into(),
            ttl,
        );

        // Build a minimal pre-signed receipt. The initiator would normally
        // co-sign it before calling run_full_handshake; we skip signing here
        // because TestHandler does not verify signatures.
        let receipt = TransactionReceipt {
            session_id: "test-session-id".to_string(),
            action: "schema:SearchAction".to_string(),
            initiating_agent_did: "did:key:zInitiator".to_string(),
            receiving_agent_did: "did:key:zTestReceiver".to_string(),
            disclosed_by_initiator: vec![],
            disclosed_by_receiver: vec![],
            executed: "schema:SearchAction executed".to_string(),
            returned: "schema:SearchResultsPage returned".to_string(),
            payment_proof_commitment: None,
            disclosure_hash: None,
            timestamp: Utc::now(),
            signatures: vec![],
            attestations: vec![],
        };

        // Run all 6 phases via the high-level API.
        let result = client
            .run_full_handshake(
                token,
                "did:key:zInitiatorEphemeral".to_string(),
                vec![], // zero disclosures
                receipt,
                ttl,
            )
            .await;

        let (cosigned_receipt, exec_result) = result.expect("run_full_handshake must succeed");

        // Phase 5 was mandatory — the receipt should carry the co-signed copy.
        assert_eq!(cosigned_receipt.action, "schema:SearchAction");
        // TestHandler appends one placeholder signature; the receipt started empty.
        assert!(
            !cosigned_receipt.signatures.is_empty(),
            "receipt must be co-signed"
        );

        // Phase 4 result should be the canned search payload.
        assert_eq!(exec_result["@type"], "SearchResultsPage");
        assert_eq!(exec_result["name"], "test result");
    }

    /// Verify that a `TokenRejected` response from Phase 1 propagates as an
    /// `Err` and does not attempt to run subsequent phases.
    #[tokio::test]
    async fn run_full_handshake_token_rejected_returns_err() {
        use std::sync::Arc;

        struct RejectingHandler;

        impl AgentHandler for RejectingHandler {
            fn handle_token(
                &self,
                _token: pap_core::session::CapabilityToken,
            ) -> Result<(String, String), TransportError> {
                Err(TransportError::RequestFailed(
                    "token rejected by policy".into(),
                ))
            }

            fn handle_did_exchange(&self, _: &str, _: &str) -> Result<(), TransportError> {
                unreachable!("should not be reached after rejection")
            }

            fn handle_disclosure(
                &self,
                _: &str,
                _: Vec<serde_json::Value>,
            ) -> Result<(), TransportError> {
                unreachable!()
            }

            fn execute(&self, _: &str) -> Result<serde_json::Value, TransportError> {
                unreachable!()
            }

            fn co_sign_receipt(
                &self,
                r: pap_core::receipt::TransactionReceipt,
            ) -> Result<pap_core::receipt::TransactionReceipt, TransportError> {
                unreachable!("{r:?}")
            }

            fn handle_close(&self, _: &str) -> Result<(), TransportError> {
                unreachable!()
            }
        }

        use chrono::{Duration, Utc};
        use pap_core::receipt::TransactionReceipt;
        use pap_core::session::CapabilityToken;

        let handler = Arc::new(RejectingHandler);
        let server = AgentServer::new(handler, 0);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AgentClient::new(&format!("http://127.0.0.1:{port}"));

        let token = CapabilityToken::mint(
            "did:key:zReceiver".into(),
            "schema:SearchAction".into(),
            "did:key:zIssuer".into(),
            Utc::now() + Duration::hours(1),
        );

        let receipt = TransactionReceipt {
            session_id: String::new(),
            action: "schema:SearchAction".into(),
            initiating_agent_did: "did:key:zInit".into(),
            receiving_agent_did: "did:key:zReceiver".into(),
            disclosed_by_initiator: vec![],
            disclosed_by_receiver: vec![],
            executed: String::new(),
            returned: String::new(),
            payment_proof_commitment: None,
            disclosure_hash: None,
            timestamp: Utc::now(),
            signatures: vec![],
            attestations: vec![],
        };

        let ttl = Utc::now() + Duration::hours(1);
        let result = client
            .run_full_handshake(token, "did:key:zEphemeral".into(), vec![], receipt, ttl)
            .await;

        assert!(
            result.is_err(),
            "token rejection must propagate as Err, got Ok"
        );
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("phase 1") || msg.contains("token rejected") || msg.contains("rejected"),
            "error message should mention token rejection, got: {msg}"
        );
    }
}
