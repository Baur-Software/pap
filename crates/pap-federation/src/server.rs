use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};

use crate::error::FederationError;
use crate::peer::{NodeIdentityResponse, RegistryPeer};
use crate::registry::FederatedRegistry;
use crate::sync::FederationMessage;

/// TLS-secured HTTP server for federation endpoints.
///
/// Exposes four routes over HTTPS:
/// - GET  /federation/identity — this node's DID + cert fingerprint
/// - GET  /federation/query?action=... — query by action type
/// - POST /federation/announce — receive an announcement
/// - GET  /federation/peers — return known peer list
///
/// All connections are TLS-encrypted using a self-signed certificate
/// whose fingerprint is published in peer discovery. No CA dependency.
///
/// CORS headers are included so browser-based agents using
/// `pap+https://` can reach federation endpoints.
pub struct FederationServer {
    registry: Arc<Mutex<FederatedRegistry>>,
    port: u16,
    node_did: String,
    node_endpoint: String,
    cert_fingerprint: String,
    tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
}

#[derive(Clone)]
struct ServerState {
    registry: Arc<Mutex<FederatedRegistry>>,
    node_did: String,
    node_endpoint: String,
    cert_fingerprint: String,
}

#[derive(Deserialize)]
struct QueryParams {
    action: String,
}

impl FederationServer {
    pub fn new(
        registry: Arc<Mutex<FederatedRegistry>>,
        port: u16,
        node_did: String,
        node_endpoint: String,
        cert_fingerprint: String,
    ) -> Self {
        Self {
            registry,
            port,
            node_did,
            node_endpoint,
            cert_fingerprint,
            tls_config: None,
        }
    }

    /// Set the TLS configuration for this server.
    pub fn with_tls(mut self, config: axum_server::tls_rustls::RustlsConfig) -> Self {
        self.tls_config = Some(config);
        self
    }

    pub fn router(&self) -> Router {
        let state = ServerState {
            registry: self.registry.clone(),
            node_did: self.node_did.clone(),
            node_endpoint: self.node_endpoint.clone(),
            cert_fingerprint: self.cert_fingerprint.clone(),
        };

        // CORS: browser agents using pap+https:// need cross-origin access
        // to federation endpoints. Allow any origin since federation is
        // public discovery — authentication is at the protocol layer (DIDs),
        // not the transport layer.
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        Router::new()
            .route("/federation/identity", get(handle_identity))
            .route("/federation/query", get(handle_query))
            .route("/federation/announce", post(handle_announce))
            .route("/federation/peers", get(handle_peers))
            .layer(cors)
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

/// Returns this node's identity — DID, endpoint, and cert fingerprint.
///
/// This is the first thing a connecting node should call. It tells them
/// who they're talking to and how to verify the TLS certificate is legit.
async fn handle_identity(State(state): State<ServerState>) -> Json<NodeIdentityResponse> {
    let registry = state.registry.lock().unwrap();
    Json(NodeIdentityResponse {
        did: state.node_did.clone(),
        endpoint: state.node_endpoint.clone(),
        cert_fingerprint: state.cert_fingerprint.clone(),
        agent_count: registry.len(),
        peer_count: registry.peers().len(),
    })
}

async fn handle_query(
    State(state): State<ServerState>,
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
    State(state): State<ServerState>,
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

async fn handle_peers(State(state): State<ServerState>) -> Json<FederationMessage> {
    let registry = state.registry.lock().unwrap();

    // Include ourselves in the peer list so connecting nodes learn about us
    let mut peers = registry.peers().to_vec();
    let self_peer = RegistryPeer::with_fingerprint(
        &state.node_did,
        &state.node_endpoint,
        &state.cert_fingerprint,
    );
    // Only add if we're not already in the list
    if !peers.iter().any(|p| p.did == state.node_did) {
        peers.push(self_peer);
    }

    Json(FederationMessage::PeerListResponse { peers })
}
