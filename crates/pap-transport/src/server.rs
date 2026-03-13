use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use pap_proto::ProtocolMessage;
use tokio::net::TcpListener;

use crate::error::TransportError;
use crate::handler::AgentHandler;

/// HTTP server for a receiving PAP agent.
///
/// Exposes the six protocol phases as REST endpoints. The transport
/// is HTTP/JSON but the handler logic is transport-agnostic.
pub struct AgentServer {
    handler: Arc<dyn AgentHandler>,
    port: u16,
}

#[derive(Clone)]
struct AppState {
    handler: Arc<dyn AgentHandler>,
}

impl AgentServer {
    pub fn new(handler: Arc<dyn AgentHandler>, port: u16) -> Self {
        Self { handler, port }
    }

    pub fn router(&self) -> Router {
        let state = AppState {
            handler: self.handler.clone(),
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

    pub async fn run(self) -> Result<(), TransportError> {
        let router = self.router();
        let addr = format!("127.0.0.1:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| TransportError::ServerError(e.to_string()))?;

        axum::serve(listener, router)
            .await
            .map_err(|e| TransportError::ServerError(e.to_string()))
    }
}

async fn handle_token(
    State(state): State<AppState>,
    Json(msg): Json<ProtocolMessage>,
) -> Result<Json<ProtocolMessage>, StatusCode> {
    match msg {
        ProtocolMessage::TokenPresentation { token } => {
            match state.handler.handle_token(token) {
                Ok((session_id, receiver_session_did)) => Ok(Json(
                    ProtocolMessage::TokenAccepted {
                        session_id,
                        receiver_session_did,
                    },
                )),
                Err(e) => Ok(Json(ProtocolMessage::TokenRejected {
                    reason: e.to_string(),
                })),
            }
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_did_exchange(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(msg): Json<ProtocolMessage>,
) -> Result<Json<ProtocolMessage>, StatusCode> {
    match msg {
        ProtocolMessage::SessionDidExchange {
            initiator_session_did,
        } => {
            state
                .handler
                .handle_did_exchange(&session_id, &initiator_session_did)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(ProtocolMessage::SessionDidAck))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_disclosure(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(msg): Json<ProtocolMessage>,
) -> Result<Json<ProtocolMessage>, StatusCode> {
    match msg {
        ProtocolMessage::DisclosureOffer { disclosures } => {
            state
                .handler
                .handle_disclosure(&session_id, disclosures)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(ProtocolMessage::DisclosureAccepted))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_execute(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<ProtocolMessage>, StatusCode> {
    let result = state
        .handler
        .execute(&session_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ProtocolMessage::ExecutionResult { result }))
}

async fn handle_receipt(
    State(state): State<AppState>,
    Path(_session_id): Path<String>,
    Json(msg): Json<ProtocolMessage>,
) -> Result<Json<ProtocolMessage>, StatusCode> {
    match msg {
        ProtocolMessage::ReceiptForCoSign { receipt } => {
            let signed = state
                .handler
                .co_sign_receipt(receipt)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            Ok(Json(ProtocolMessage::ReceiptCoSigned { receipt: signed }))
        }
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

async fn handle_close(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<ProtocolMessage>, StatusCode> {
    state
        .handler
        .handle_close(&session_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(ProtocolMessage::SessionClosed))
}
