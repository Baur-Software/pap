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
use crate::ohttp::{OhttpConfig, OhttpServerDecryptor, OhttpServerEncryptor};

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
}

#[derive(Clone)]
struct AppState {
    handler: Arc<dyn AgentHandler>,
    ohttp_decryptor: Option<OhttpServerDecryptor>,
    ohttp_encryptor: Option<OhttpServerEncryptor>,
}

impl AgentServer {
    pub fn new(handler: Arc<dyn AgentHandler>, port: u16) -> Self {
        Self {
            handler,
            port,
            tls_config: None,
            ohttp_config: None,
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

    pub fn router(&self) -> Router {
        let ohttp_decryptor = self.ohttp_config.as_ref().map(|cfg| {
            OhttpServerDecryptor::new(cfg.clone())
        });
        let ohttp_encryptor = self.ohttp_config.as_ref().map(|cfg| {
            OhttpServerEncryptor::new(cfg.clone())
        });

        let state = AppState {
            handler: self.handler.clone(),
            ohttp_decryptor,
            ohttp_encryptor,
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
async fn decode_request_body(
    body: Bytes,
    state: &AppState,
) -> Result<ProtocolMessage, StatusCode> {
    if let Some(ref decryptor) = state.ohttp_decryptor {
        // Decrypt OHTTP payload
        let plaintext = decryptor
            .decrypt_request(&body)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        serde_json::from_slice(&plaintext).map_err(|_| StatusCode::BAD_REQUEST)
    } else {
        // Parse JSON directly
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)
    }
}

/// Encode response message in OHTTP if enabled, otherwise return as JSON.
fn encode_response_body(
    msg: ProtocolMessage,
    state: &AppState,
) -> Result<Vec<u8>, StatusCode> {
    let json = serde_json::to_vec(&msg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(ref encryptor) = state.ohttp_encryptor {
        // Encrypt with OHTTP
        encryptor
            .encrypt_response(&json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        // Return JSON directly
        Ok(json)
    }
}

async fn handle_token(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let msg = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::TokenPresentation { token } => match state.handler.handle_token(token) {
            Ok((session_id, receiver_session_did)) => {
                let response = ProtocolMessage::TokenAccepted {
                    session_id,
                    receiver_session_did,
                };
                encode_response_body(response, &state)
            }
            Err(e) => {
                let response = ProtocolMessage::TokenRejected {
                    reason: e.to_string(),
                };
                encode_response_body(response, &state)
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
    let msg = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        } => {
            state
                .handler
                .handle_did_exchange(&session_id, &initiator_session_did)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let response = ProtocolMessage::SessionDidAck;
            encode_response_body(response, &state)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_disclosure(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let msg = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::DisclosureOffer { disclosures } => {
            state
                .handler
                .handle_disclosure(&session_id, disclosures)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let response = ProtocolMessage::DisclosureAccepted;
            encode_response_body(response, &state)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_execute(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    let result = state
        .handler
        .execute(&session_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response = ProtocolMessage::ExecutionResult { result };
    encode_response_body(response, &state)
}

async fn handle_receipt(
    State(state): State<AppState>,
    Path(_session_id): Path<String>,
    body: Bytes,
) -> Result<Vec<u8>, StatusCode> {
    let msg = decode_request_body(body, &state).await?;

    match msg {
        ProtocolMessage::ReceiptForCoSign { receipt } => {
            let signed = state
                .handler
                .co_sign_receipt(receipt)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            let response = ProtocolMessage::ReceiptCoSigned { receipt: signed };
            encode_response_body(response, &state)
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_close(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Vec<u8>, StatusCode> {
    state
        .handler
        .handle_close(&session_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let response = ProtocolMessage::SessionClosed;
    encode_response_body(response, &state)
}
