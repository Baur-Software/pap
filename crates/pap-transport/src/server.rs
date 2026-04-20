use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use pap_proto::ProtocolMessage;
use tokio::net::TcpListener;

use crate::error::TransportError;
use crate::handler::AgentHandler;
use crate::ohttp::{OhttpConfig, OhttpResponseEncryptCtx, OhttpServerDecryptor};

/// Default per-frame size limit: 1 MiB.
///
/// This is large enough for typical PAP messages, including ExecutionResult
/// payloads that carry embedded JSON-LD content, while ensuring a single
/// malformed or malicious frame cannot exhaust server memory.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1 * 1024 * 1024;

/// TLS-secured HTTP server for a receiving PAP agent.
///
/// Exposes the six protocol phases as REST endpoints over HTTPS.
/// The transport is HTTPS/JSON but the handler logic is transport-agnostic.
///
/// Optionally supports RFC 9458 Oblivious HTTP encapsulation for privacy
/// through untrusted relays.
pub struct AgentServer {
    handler: Arc<dyn AgentHandler>,
    port: u16,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
    ohttp_config: Option<OhttpConfig>,
    /// Maximum allowed size (in bytes) for any single incoming message frame.
    ///
    /// Requests whose body exceeds this limit are rejected with HTTP 400 before
    /// deserialization begins, preventing allocation-based DoS attacks.
    /// Defaults to [`DEFAULT_MAX_MESSAGE_BYTES`] (1 MiB).
    max_message_bytes: usize,
}

#[derive(Clone)]
struct AppState {
    handler: Arc<dyn AgentHandler>,
    ohttp_decryptor: Option<OhttpServerDecryptor>,
    /// Per-frame size limit propagated into every request handler.
    max_message_bytes: usize,
    // Response encryption context flows per-request from decrypt_request — no stored encryptor.
}

impl AgentServer {
    pub fn new(handler: Arc<dyn AgentHandler>, port: u16) -> Self {
        Self {
            handler,
            port,
            tls_config: None,
            ohttp_config: None,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }

    /// Set the TLS configuration for this server.
    pub fn with_tls(mut self, config: axum_server::tls_rustls::RustlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Enable RFC 9458 Oblivious HTTP for this server.
    pub fn with_ohttp(mut self, config: OhttpConfig) -> Self {
        self.ohttp_config = Some(config);
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

    pub fn router(&self) -> Router {
        let ohttp_decryptor = self
            .ohttp_config
            .as_ref()
            .map(|cfg| OhttpServerDecryptor::new(cfg.clone()));

        let state = AppState {
            handler: self.handler.clone(),
            ohttp_decryptor,
            max_message_bytes: self.max_message_bytes,
        };

        Router::new()
            .route("/session", post(handle_token))
            .route("/session/{id}/did", post(handle_did_exchange))
            .route("/session/{id}/disclosure", post(handle_disclosure))
            .route("/session/{id}/execute", post(handle_execute))
            .route("/session/{id}/receipt", post(handle_receipt))
            .route("/session/{id}/close", post(handle_close))
            .with_state(state)
    }

    /// Run the server. TLS if configured, plaintext otherwise (tests only).
    pub async fn run(self) -> Result<(), TransportError> {
        let router = self.router();
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));

        if let Some(tls_config) = self.tls_config {
            axum_server::bind_rustls(addr, tls_config)
                .serve(router.into_make_service())
                .await
                .map_err(|e| TransportError::ServerError(e.to_string()))
        } else {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| TransportError::ServerError(e.to_string()))?;
            axum::serve(listener, router)
                .await
                .map_err(|e| TransportError::ServerError(e.to_string()))
        }
    }
}

/// Decode request body from OHTTP if enabled, otherwise parse as JSON.
///
/// Rejects any frame whose byte length exceeds `state.max_message_bytes` with
/// HTTP 400 before any deserialization work is performed.  This prevents an
/// attacker from allocating arbitrary amounts of memory by sending oversized
/// frames (CVE-class: allocation-based DoS).
///
/// Returns `(message, response_ctx)` where `response_ctx` must be passed to
/// `encode_response_body` to ensure the response uses the correct HPKE-derived key.
async fn decode_request_body(
    body: Bytes,
    state: &AppState,
) -> Result<(ProtocolMessage, Option<OhttpResponseEncryptCtx>), StatusCode> {
    if let Some(ref decryptor) = state.ohttp_decryptor {
        // Check the ciphertext size before decryption; the plaintext will be
        // at most this size, so this is a valid upper bound.
        if body.len() > state.max_message_bytes {
            return Err(StatusCode::BAD_REQUEST);
        }
        let (plaintext, ctx) = decryptor
            .decrypt_request(&body)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        // Also check the decrypted plaintext size.
        if plaintext.len() > state.max_message_bytes {
            return Err(StatusCode::BAD_REQUEST);
        }
        let msg = serde_json::from_slice(&plaintext).map_err(|_| StatusCode::BAD_REQUEST)?;
        Ok((msg, Some(ctx)))
    } else {
        if body.len() > state.max_message_bytes {
            return Err(StatusCode::BAD_REQUEST);
        }
        let msg = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        Ok((msg, None))
    }
}

/// Encode response message in OHTTP if a response context was provided, otherwise as JSON.
fn encode_response_body(
    msg: ProtocolMessage,
    ctx: Option<OhttpResponseEncryptCtx>,
) -> Result<Vec<u8>, StatusCode> {
    let json = serde_json::to_vec(&msg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(c) = ctx {
        c.encrypt_response(&json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Ok(json)
    }
}

async fn handle_token(State(state): State<AppState>, body: Bytes) -> Result<Vec<u8>, StatusCode> {
    let (msg, ctx) = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::TokenPresentation { token } => match state.handler.handle_token(token) {
            Ok((session_id, receiver_session_did)) => {
                let response = ProtocolMessage::TokenAccepted {
                    session_id,
                    receiver_session_did,
                    attestation: None,
                };
                encode_response_body(response, ctx)
            }
            Err(e) => {
                let response = ProtocolMessage::TokenRejected {
                    reason: e.to_string(),
                };
                encode_response_body(response, ctx)
            }
        },
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_did_exchange(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let (msg, ctx) = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        } => {
            state
                .handler
                .handle_did_exchange(&session_id, &initiator_session_did)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let response = ProtocolMessage::SessionDidAck;
            encode_response_body(response, ctx)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_disclosure(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let (msg, ctx) = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::DisclosureOffer { disclosures } => {
            state
                .handler
                .handle_disclosure(&session_id, disclosures)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let response = ProtocolMessage::DisclosureAccepted;
            encode_response_body(response, ctx)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_execute(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    // Decode the (possibly empty) OHTTP-wrapped body to establish the response context.
    // The client sends an encrypted empty JSON object; decrypting it gives us the key
    // material needed to encrypt the execution result response.
    let ctx = if body.is_empty() {
        None
    } else {
        match &state.ohttp_decryptor {
            Some(d) => {
                let (_, ctx) = d
                    .decrypt_request(&body)
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                Some(ctx)
            }
            None => None,
        }
    };

    // Agent executors use reqwest::blocking::Client, which panics inside a
    // tokio async context.  Offload to spawn_blocking so the blocking I/O
    // runs on a dedicated thread-pool thread.
    let handler = state.handler.clone();
    let sid = session_id.clone();
    let result = tokio::task::spawn_blocking(move || handler.execute(&sid))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response = ProtocolMessage::ExecutionResult { result };
    encode_response_body(response, ctx)
}

async fn handle_receipt(
    State(state): State<AppState>,
    Path(_session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let (msg, ctx) = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::ReceiptForCoSign { receipt } => {
            let signed = state
                .handler
                .co_sign_receipt(receipt)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let response = ProtocolMessage::ReceiptCoSigned { receipt: signed };
            encode_response_body(response, ctx)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_close(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    // Decode the OHTTP-wrapped close message to establish the response context.
    let ctx = if body.is_empty() {
        None
    } else {
        let (_, ctx) = decode_request_body(body, &state).await?;
        ctx
    };

    state
        .handler
        .handle_close(&session_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response = ProtocolMessage::SessionClosed;
    encode_response_body(response, ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Bytes;

    // ── decode_request_body size-limit tests ─────────────────────────────

    fn make_state(limit: usize) -> AppState {
        use crate::handler::AgentHandler;
        use pap_core::{receipt::TransactionReceipt, session::CapabilityToken};
        use std::sync::Arc;

        struct NopHandler;
        impl AgentHandler for NopHandler {
            fn handle_token(
                &self,
                _: CapabilityToken,
            ) -> Result<(String, String), TransportError> {
                Ok(("s".into(), "did:key:z".into()))
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

        AppState {
            handler: Arc::new(NopHandler),
            ohttp_decryptor: None,
            max_message_bytes: limit,
        }
    }

    /// A body that exceeds the limit must be rejected with HTTP 400
    /// (StatusCode::BAD_REQUEST) before any deserialization is attempted.
    #[tokio::test]
    async fn http_body_exceeding_limit_returns_bad_request() {
        // Limit of 10 bytes; send 1024 bytes.
        let state = make_state(10);
        let oversized = Bytes::from(vec![b'x'; 1024]);

        let result = decode_request_body(oversized, &state).await;
        assert!(
            matches!(result, Err(StatusCode::BAD_REQUEST)),
            "oversized body must be rejected with 400"
        );
    }

    /// A body of exactly one byte over the limit must also be rejected.
    #[tokio::test]
    async fn http_body_one_byte_over_limit_returns_bad_request() {
        let limit: usize = 64;
        let state = make_state(limit);
        let one_over = Bytes::from(vec![b'a'; limit + 1]);

        let result = decode_request_body(one_over, &state).await;
        assert!(
            matches!(result, Err(StatusCode::BAD_REQUEST)),
            "body one byte over limit must be rejected with 400"
        );
    }

    /// A body exactly at the limit must pass the size check (parse may still
    /// fail, but not due to the size guard).
    #[tokio::test]
    async fn http_body_at_limit_passes_size_check() {
        // Use valid JSON so the whole function succeeds.
        let valid_json = serde_json::to_vec(&serde_json::json!({
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
        }))
        .unwrap();

        let limit = valid_json.len(); // exactly the size of the payload
        let state = make_state(limit);
        let body = Bytes::from(valid_json);

        // Should not return BAD_REQUEST due to size check.
        // Any error here would be a JSON parse error, not a size error.
        let result = decode_request_body(body, &state).await;
        assert!(
            !matches!(result, Err(StatusCode::BAD_REQUEST)),
            "body exactly at the limit must not be rejected by the size guard"
        );
    }
}
