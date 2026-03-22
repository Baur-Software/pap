mod config;
mod routes;
mod state;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::info;

use pap_did::PrincipalKeypair;
use pap_federation::registry::FederatedRegistry;
use pap_federation::server::FederationServer;

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("pap_registry=info".parse().unwrap()),
        )
        .init();

    let config = Config::from_env();

    info!("Starting PAP Registry on {}:{}", config.host, config.port);

    // Generate a fresh Ed25519 node identity (DID) at startup.
    // Production deployments should persist the signing key across restarts.
    let node_keypair = PrincipalKeypair::generate();
    let node_did = node_keypair.did();

    // Generate a self-signed TLS certificate bound to the node's DID.
    let tls_identity = pap_federation::generate_node_identity(&node_did)?;
    let cert_fingerprint = tls_identity.fingerprint.clone();

    info!("Node DID: {}", node_did);
    info!("Cert fingerprint: {}", cert_fingerprint);

    let registry = Arc::new(Mutex::new(FederatedRegistry::new()));
    let app_state = AppState::new(
        registry.clone(),
        node_did.clone(),
        &config,
        cert_fingerprint.clone(),
    );

    // Federation protocol routes (PAP-compatible — usable by any PAP client).
    // The FederationServer sets its own internal ServerState on the router.
    let federation_router = FederationServer::new(
        registry.clone(),
        config.port,
        node_did,
        config.public_endpoint.clone(),
        cert_fingerprint,
    )
    .router();

    // Admin API routes — use AppState (separate from federation's ServerState).
    let admin_router = routes::admin::router().with_state(app_state);

    // Static file serving for the web UI (falls back to index.html for SPA routing)
    let dist_dir = config.dist_dir.clone();
    let index_fallback = format!("{}/index.html", dist_dir);

    let static_service =
        ServeDir::new(&dist_dir).not_found_service(ServeFile::new(&index_fallback));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .merge(federation_router)
        .merge(admin_router)
        .fallback_service(static_service)
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("Registry running on http://{}", addr);
    info!("Admin UI available at http://{}/", addr);
    info!(
        "Federation endpoint: http://{}/federation/identity",
        addr
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
