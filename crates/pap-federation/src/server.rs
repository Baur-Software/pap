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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn make_server() -> FederationServer {
        let registry = Arc::new(Mutex::new(FederatedRegistry::new()));
        FederationServer::new(
            registry,
            7890,
            "did:key:zTestNode".into(),
            "https://localhost:7890".into(),
            "abc123fingerprint".into(),
        )
    }

    fn make_server_with_ad() -> FederationServer {
        let mut reg = FederatedRegistry::new();

        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();
        let mut ad = pap_marketplace::AgentAdvertisement::new(
            "Test Agent",
            "TestCorp",
            &did,
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec!["schema:SearchResult".into()],
        );
        ad.sign(&key).unwrap();
        reg.register_local(ad).unwrap();

        let registry = Arc::new(Mutex::new(reg));
        FederationServer::new(
            registry,
            7890,
            "did:key:zTestNode".into(),
            "https://localhost:7890".into(),
            "abc123fingerprint".into(),
        )
    }

    #[tokio::test]
    async fn identity_endpoint_returns_node_info() {
        let server = make_server();
        let app = server.router();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/federation/identity")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let identity: NodeIdentityResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(identity.did, "did:key:zTestNode");
        assert_eq!(identity.endpoint, "https://localhost:7890");
        assert_eq!(identity.cert_fingerprint, "abc123fingerprint");
        assert_eq!(identity.agent_count, 0);
        assert_eq!(identity.peer_count, 0);
    }

    #[tokio::test]
    async fn query_endpoint_returns_matching_ads() {
        let server = make_server_with_ad();
        let app = server.router();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/federation/query?action=schema:SearchAction")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let msg: FederationMessage = serde_json::from_slice(&body).unwrap();
        match msg {
            FederationMessage::QueryResponse { advertisements } => {
                assert_eq!(advertisements.len(), 1);
                assert_eq!(advertisements[0].name, "Test Agent");
            }
            _ => panic!("expected QueryResponse"),
        }
    }

    #[tokio::test]
    async fn query_endpoint_returns_empty_for_unknown_action() {
        let server = make_server_with_ad();
        let app = server.router();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/federation/query?action=schema:UnknownAction")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let msg: FederationMessage = serde_json::from_slice(&body).unwrap();
        match msg {
            FederationMessage::QueryResponse { advertisements } => {
                assert!(advertisements.is_empty());
            }
            _ => panic!("expected QueryResponse"),
        }
    }

    #[tokio::test]
    async fn peers_endpoint_includes_self() {
        let server = make_server();
        let app = server.router();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/federation/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let msg: FederationMessage = serde_json::from_slice(&body).unwrap();
        match msg {
            FederationMessage::PeerListResponse { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].did, "did:key:zTestNode");
                assert_eq!(peers[0].cert_fingerprint, Some("abc123fingerprint".into()));
            }
            _ => panic!("expected PeerListResponse"),
        }
    }

    #[tokio::test]
    async fn announce_endpoint_accepts_signed_ad() {
        let server = make_server();
        let app = server.router();

        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();
        let mut ad = pap_marketplace::AgentAdvertisement::new(
            "New Agent",
            "Corp",
            &did,
            vec!["schema:BookAction".into()],
            vec![],
            vec![],
            vec![],
        );
        ad.sign(&key).unwrap();

        let msg = FederationMessage::Announce {
            advertisement: Box::new(ad),
        };
        let body = serde_json::to_string(&msg).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/federation/announce")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let ack: FederationMessage = serde_json::from_slice(&body).unwrap();
        match ack {
            FederationMessage::AnnounceAck { accepted, .. } => {
                assert!(accepted);
            }
            _ => panic!("expected AnnounceAck"),
        }
    }

    #[tokio::test]
    async fn announce_endpoint_rejects_non_announce_message() {
        let server = make_server();
        let app = server.router();

        let msg = FederationMessage::PeerList;
        let body = serde_json::to_string(&msg).unwrap();

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/federation/announce")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let ack: FederationMessage = serde_json::from_slice(&body).unwrap();
        match ack {
            FederationMessage::AnnounceAck { accepted, hash } => {
                assert!(!accepted);
                assert!(hash.is_empty());
            }
            _ => panic!("expected AnnounceAck"),
        }
    }

    #[tokio::test]
    async fn cors_preflight_returns_access_control_headers() {
        let server = make_server();
        let app = server.router();

        let resp = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/federation/identity")
                    .header("origin", "https://browser-app.example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn cors_response_includes_allow_origin() {
        let server = make_server();
        let app = server.router();

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/federation/identity")
                    .header("origin", "https://browser-app.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(allow_origin, "*");
    }
}
