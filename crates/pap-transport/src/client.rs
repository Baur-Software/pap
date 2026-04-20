use chrono::{DateTime, Utc};
use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_proto::ProtocolMessage;

use crate::error::TransportError;
use crate::server::DEFAULT_MAX_MESSAGE_BYTES;

/// HTTP client for an initiating PAP agent.
///
/// Drives the six-phase handshake by sending protocol messages to
/// a receiving agent's HTTP server.
///
/// # Recommended usage
///
/// Use [`AgentClient::run_full_handshake`] for all standard handshake sequences.
/// It enforces the correct phase ordering and makes Phase 5 (co-signed receipt)
/// mandatory — the primary accountability mechanism of the protocol.
///
/// The individual phase methods (`present_token`, `exchange_did`, etc.) are
/// retained as low-level APIs for advanced use cases such as streaming sessions
/// or custom error recovery, but they make it easy to accidentally omit Phase 5.
pub struct AgentClient {
    base_url: String,
    client: reqwest::Client,
}

/// Check that the mandate TTL has not elapsed.
///
/// Called at the start of each phase method that has access to the mandate
/// expiry (spec §5.5: "TTL bounds are verified cryptographically at each
/// level of the mandate chain").
fn check_mandate_ttl(expires_at: DateTime<Utc>) -> Result<(), TransportError> {
    if Utc::now() > expires_at {
        return Err(TransportError::MandateExpired);
    }
    Ok(())
}


/// Consume an HTTP response body with a size cap before deserialization.
///
/// Rejects responses larger than [`DEFAULT_MAX_MESSAGE_BYTES`] with
/// [`TransportError::MessageTooLarge`] before the JSON allocator can grow
/// unboundedly — the client-side equivalent of the server's `decode_request_body`
/// size guard.
async fn decode_response(resp: reqwest::Response) -> Result<ProtocolMessage, TransportError> {
    use std::io::Cursor;
    use crate::limited_read::{LimitedRead, is_limit_exceeded};
    let limit = DEFAULT_MAX_MESSAGE_BYTES;
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| TransportError::InvalidResponse(e.to_string()))?;
    serde_json::from_reader(LimitedRead::new(Cursor::new(&bytes[..]), limit)).map_err(|e| {
        if is_limit_exceeded(&e) {
            TransportError::MessageTooLarge { size: bytes.len(), limit }
        } else {
            TransportError::InvalidResponse(e.to_string())
        }
    })
}

impl AgentClient {
    /// Create a new agent client with standard TLS settings.
    ///
    /// Uses system CA roots. For PAP federation connections (self-signed
    /// certs), use `with_client()` with a fingerprint-pinned reqwest
    /// client from `pap_federation::build_pinned_client()`.
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create an agent client with a pre-configured reqwest client.
    ///
    /// Use this when you need a client with specific TLS settings,
    /// e.g. pinned peer certificate fingerprints.
    pub fn with_client(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Run the complete 6-phase PAP handshake in the correct sequence.
    ///
    /// This is the **recommended high-level API** for all standard agent
    /// interactions. It sequences the phases as required by the PAP spec:
    ///
    /// 1. **TokenPresentation** — present the capability token; receive the
    ///    session ID and the receiver's ephemeral session DID.
    /// 2. **SessionDIDExchange** — send the initiator's ephemeral session DID.
    /// 3. **DisclosureOffer** — send selective disclosures (pass an empty
    ///    `Vec` for zero-disclosure sessions).
    /// 4. **Execution** — request execution; receive the Schema.org result.
    /// 5. **ReceiptCoSign** — send the half-signed receipt and receive the
    ///    co-signed copy back. **This phase is mandatory.** Skipping it
    ///    removes the bilateral accountability record for the session.
    /// 6. **SessionClose** — close the session; ephemeral keys are discarded.
    ///
    /// # Returns
    ///
    /// `Ok((receipt, result))` where `receipt` is the fully co-signed
    /// [`TransactionReceipt`] (both initiator and receiver signatures) and
    /// `result` is the Schema.org JSON-LD execution output from Phase 4.
    ///
    /// If any phase returns an unexpected message or a protocol error, the
    /// session is closed before returning `Err`. Callers should treat a
    /// returned `Err` as a closed session and discard all session state.
    ///
    /// # Arguments
    ///
    /// * `token` — a signed [`CapabilityToken`] authorising this interaction.
    /// * `initiator_session_did` — the initiator's ephemeral session DID for
    ///   Phase 2. Generate one with `pap_did::SessionKeypair::generate()`.
    /// * `disclosures` — SD-JWT disclosure values for Phase 3. Pass `vec![]`
    ///   for zero-disclosure sessions.
    /// * `receipt` — a [`TransactionReceipt`] pre-signed by the initiator,
    ///   ready for the receiver to co-sign in Phase 5.
    /// * `mandate_expires_at` — the mandate TTL checked at each phase
    ///   transition before any network I/O is performed (spec §5.5).
    pub async fn run_full_handshake(
        &self,
        token: CapabilityToken,
        initiator_session_did: String,
        disclosures: Vec<serde_json::Value>,
        receipt: TransactionReceipt,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<(TransactionReceipt, serde_json::Value), TransportError> {
        // ── Phase 1: Token Presentation ──────────────────────────────────
        let phase1 = self.present_token(token).await?;
        let session_id = match phase1 {
            ProtocolMessage::TokenAccepted { session_id, .. } => session_id,
            ProtocolMessage::TokenRejected { reason } => {
                return Err(TransportError::RequestFailed(format!(
                    "phase 1 token rejected: {reason}"
                )));
            }
            other => {
                return Err(TransportError::InvalidResponse(format!(
                    "phase 1: expected TokenAccepted, got {}",
                    other.message_type()
                )));
            }
        };

        // ── Phase 2: Ephemeral DID Exchange ──────────────────────────────
        let phase2 = self
            .exchange_did(&session_id, initiator_session_did, mandate_expires_at)
            .await;
        let phase2 = match phase2 {
            Ok(msg) => msg,
            Err(e) => {
                let _ = self.close_session(&session_id, mandate_expires_at).await;
                return Err(e);
            }
        };
        if !matches!(phase2, ProtocolMessage::SessionDidAck) {
            let _ = self.close_session(&session_id, mandate_expires_at).await;
            return Err(TransportError::InvalidResponse(format!(
                "phase 2: expected SessionDidAck, got {}",
                phase2.message_type()
            )));
        }

        // ── Phase 3: Disclosure ───────────────────────────────────────────
        let phase3 = self
            .send_disclosures(&session_id, disclosures, mandate_expires_at)
            .await;
        let phase3 = match phase3 {
            Ok(msg) => msg,
            Err(e) => {
                let _ = self.close_session(&session_id, mandate_expires_at).await;
                return Err(e);
            }
        };
        if !matches!(phase3, ProtocolMessage::DisclosureAccepted) {
            let _ = self.close_session(&session_id, mandate_expires_at).await;
            return Err(TransportError::InvalidResponse(format!(
                "phase 3: expected DisclosureAccepted, got {}",
                phase3.message_type()
            )));
        }

        // ── Phase 4: Execution ────────────────────────────────────────────
        let phase4 = self
            .request_execution(&session_id, mandate_expires_at)
            .await;
        let phase4 = match phase4 {
            Ok(msg) => msg,
            Err(e) => {
                let _ = self.close_session(&session_id, mandate_expires_at).await;
                return Err(e);
            }
        };
        let exec_result = match phase4 {
            ProtocolMessage::ExecutionResult { result } => result,
            other => {
                let _ = self.close_session(&session_id, mandate_expires_at).await;
                return Err(TransportError::InvalidResponse(format!(
                    "phase 4: expected ExecutionResult, got {}",
                    other.message_type()
                )));
            }
        };

        // ── Phase 5: Receipt Co-signing (mandatory) ───────────────────────
        let phase5 = self
            .exchange_receipt(&session_id, receipt, mandate_expires_at)
            .await;
        let phase5 = match phase5 {
            Ok(msg) => msg,
            Err(e) => {
                let _ = self.close_session(&session_id, mandate_expires_at).await;
                return Err(e);
            }
        };
        let cosigned_receipt = match phase5 {
            ProtocolMessage::ReceiptCoSigned { receipt } => receipt,
            other => {
                let _ = self.close_session(&session_id, mandate_expires_at).await;
                return Err(TransportError::InvalidResponse(format!(
                    "phase 5: expected ReceiptCoSigned, got {}",
                    other.message_type()
                )));
            }
        };

        // ── Phase 6: Session Close ────────────────────────────────────────
        let phase6 = self.close_session(&session_id, mandate_expires_at).await?;
        if !matches!(phase6, ProtocolMessage::SessionClosed) {
            return Err(TransportError::InvalidResponse(format!(
                "phase 6: expected SessionClosed, got {}",
                phase6.message_type()
            )));
        }

        Ok((cosigned_receipt, exec_result))
    }

    /// Low-level API. Prefer [`AgentClient::run_full_handshake`] for standard use cases.
    ///
    /// Phase 1: Present a capability token. Returns session_id and
    /// receiver's ephemeral session DID on acceptance.
    pub async fn present_token(
        &self,
        token: CapabilityToken,
    ) -> Result<ProtocolMessage, TransportError> {
        let msg = ProtocolMessage::TokenPresentation { token };
        let resp = self
            .client
            .post(format!("{}/session", self.base_url))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        decode_response(resp).await
    }

    /// Low-level API. Prefer [`AgentClient::run_full_handshake`] for standard use cases.
    ///
    /// Phase 2: Send the initiator's ephemeral session DID.
    ///
    /// `mandate_expires_at` is checked before the network request is made.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn exchange_did(
        &self,
        session_id: &str,
        initiator_session_did: String,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        check_mandate_ttl(mandate_expires_at)?;
        let msg = ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        };
        let resp = self
            .client
            .post(format!("{}/session/{}/did", self.base_url, session_id))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        decode_response(resp).await
    }

    /// Low-level API. Prefer [`AgentClient::run_full_handshake`] for standard use cases.
    ///
    /// Phase 3: Send selective disclosures (or empty vec for zero-disclosure).
    ///
    /// `mandate_expires_at` is checked before the network request is made.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn send_disclosures(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        check_mandate_ttl(mandate_expires_at)?;
        let msg = ProtocolMessage::DisclosureOffer { disclosures };
        let resp = self
            .client
            .post(format!(
                "{}/session/{}/disclosure",
                self.base_url, session_id
            ))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        decode_response(resp).await
    }

    /// Low-level API. Prefer [`AgentClient::run_full_handshake`] for standard use cases.
    ///
    /// Phase 4: Request execution and receive the result.
    ///
    /// `mandate_expires_at` is checked before the network request is made.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn request_execution(
        &self,
        session_id: &str,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        check_mandate_ttl(mandate_expires_at)?;
        let resp = self
            .client
            .post(format!("{}/session/{}/execute", self.base_url, session_id))
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        decode_response(resp).await
    }

    /// Low-level API. Prefer [`AgentClient::run_full_handshake`] for standard use cases.
    ///
    /// Phase 5: Send a receipt for co-signing. Returns the co-signed receipt.
    ///
    /// `mandate_expires_at` is checked before the network request is made.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn exchange_receipt(
        &self,
        session_id: &str,
        receipt: TransactionReceipt,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        check_mandate_ttl(mandate_expires_at)?;
        let msg = ProtocolMessage::ReceiptForCoSign { receipt };
        let resp = self
            .client
            .post(format!("{}/session/{}/receipt", self.base_url, session_id))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        decode_response(resp).await
    }

    /// Low-level API. Prefer [`AgentClient::run_full_handshake`] for standard use cases.
    ///
    /// Phase 6: Close the session.
    ///
    /// `mandate_expires_at` is checked before the network request is made.
    /// Returns [`TransportError::MandateExpired`] if the mandate TTL has
    /// elapsed (spec §5.5).
    pub async fn close_session(
        &self,
        session_id: &str,
        mandate_expires_at: DateTime<Utc>,
    ) -> Result<ProtocolMessage, TransportError> {
        check_mandate_ttl(mandate_expires_at)?;
        let msg = ProtocolMessage::SessionClose {
            session_id: session_id.to_string(),
        };
        let resp = self
            .client
            .post(format!("{}/session/{}/close", self.base_url, session_id))
            .json(&msg)
            .send()
            .await
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

        decode_response(resp).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::DEFAULT_MAX_MESSAGE_BYTES;

    // ── decode_response size-limit test ──────────────────────────────────

    /// Spin up an Axum server that returns a body one byte larger than the
    /// allowed maximum. `present_token()` must reject it with `MessageTooLarge`.
    #[tokio::test]
    async fn http_client_oversized_response_rejected() {
        use axum::{body::Body, response::Response, routing::post, Router};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Handler that always returns DEFAULT_MAX_MESSAGE_BYTES + 1 bytes of 'x'.
        async fn oversized_handler() -> Response {
// Must be valid JSON so serde_json reads past the first token before
            // LimitedRead trips.  Wrap in a JSON string value.
            let payload = "a".repeat(DEFAULT_MAX_MESSAGE_BYTES);
            let body = format!(r#"{{"t":"{}"}}"#, payload);
            Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }

        let router = Router::new().route("/session", post(oversized_handler));
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        // Give the server a moment.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = AgentClient::new(&format!("http://127.0.0.1:{port}"));

        use chrono::{Duration, Utc};
        use pap_core::session::CapabilityToken;
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
