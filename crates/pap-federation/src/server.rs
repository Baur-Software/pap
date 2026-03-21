use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::error::FederationError;
use crate::registry::FederatedRegistry;
use crate::sync::FederationMessage;

/// TLS-secured HTTP server for federation endpoints.
///
/// Exposes three routes over HTTPS:
/// - GET  /federation/query?action=... — query by action type
/// - POST /federation/announce — receive an announcement
/// - GET  /federation/peers — return known peer list
///
/// All connections are TLS-encrypted using a self-signed certificate
/// whose fingerprint is published in peer discovery. No CA dependency.
pub struct FederationServer {
    registry: Arc<Mutex<FederatedRegistry>>,
    port: u16,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
}

#[derive(Clone)]
struct AppState {
    registry: Arc<Mutex<FederatedRegistry>>,
}

#[derive(Deserialize)]
struct QueryParams {
    action: String,
}

impl FederationServer {
    pub fn new(registry: Arc<Mutex<FederatedRegistry>>, port: u16) -> Self {
        Self {
            registry,
            port,
            tls_config: None,
        }
    }

    /// Set the TLS configuration for this server.
    pub fn with_tls(mut self, config: axum_server::tls_rustls::RustlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub fn router(&self) -> Router {
        let state = AppState {
            registry: self.registry.clone(),
        };

        Router::new()
            .route("/federation/query", get(handle_query))
            .route("/federation/announce", post(handle_announce))
            .route("/federation/peers", get(handle_peers))
            .with_state(state)
    }

    /// Run the server. TLS if configured, plaintext otherwise (tests only).
    pub async fn run(self) -> Result<(), FederationError> {
        let router = self.router();
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));

        if let Some(tls_config) = self.tls_config {
            axum_server::bind_rustls(addr, tls_config)
                .serve(router.into_make_service())
                .await
                .map_err(|e| FederationError::ServerError(e.to_string()))
        } else {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| FederationError::ServerError(e.to_string()))?;
            axum::serve(listener, router)
                .await
                .map_err(|e| FederationError::ServerError(e.to_string()))
        }
    }
}

async fn handle_query(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
) -> Json<FederationMessage> {
    let registry = state.registry.lock().unwrap();
    let ads: Vec<_> = registry
        .query_local(&params.action)
        .into_iter()
        .cloned()
        .collect();

    Json(FederationMessage::QueryResponse {
        advertisements: ads,
    })
}

async fn handle_announce(
    State(state): State<AppState>,
    Json(msg): Json<FederationMessage>,
) -> Json<FederationMessage> {
    match msg {
        FederationMessage::Announce { advertisement } => {
            let hash = advertisement.hash();
            let mut registry = state.registry.lock().unwrap();
            let accepted = registry.merge_remote(vec![*advertisement]) > 0;
            Json(FederationMessage::AnnounceAck { hash, accepted })
        }
        _ => Json(FederationMessage::AnnounceAck {
            hash: String::new(),
            accepted: false,
        }),
    }
}

async fn handle_peers(State(state): State<AppState>) -> Json<FederationMessage> {
    let registry = state.registry.lock().unwrap();
    let peers = registry.peers().to_vec();
    Json(FederationMessage::PeerListResponse { peers })
}
