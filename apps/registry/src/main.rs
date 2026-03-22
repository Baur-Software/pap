mod config;
mod db;
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
use crate::db::{DbConfig, NodeIdentity, RegistryStore};
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

    // ── Database setup ────────────────────────────────────────────────────────
    let db_cfg = DbConfig::resolve();
    let store = RegistryStore::connect(&db_cfg).await?;
    store.migrate().await?;
    let store = Arc::new(store);

    // ── Node identity (persisted across restarts) ─────────────────────────────
    let node_keypair = match store.load_identity().await? {
        Some(identity) => {
            info!("Loaded persisted node identity: {}", identity.did);
            PrincipalKeypair::from_bytes(&identity.signing_key_bytes)?
        }
        None => {
            let kp = PrincipalKeypair::generate();
            let identity = NodeIdentity {
                did: kp.did(),
                signing_key_bytes: kp.signing_key().to_bytes(),
            };
            store.save_identity(&identity).await?;
            info!("Generated and persisted new node identity: {}", identity.did);
            kp
        }
    };
    let node_did = node_keypair.did();

    // TLS cert is still ephemeral — bound to the (now stable) DID.
    let tls_identity = pap_federation::generate_node_identity(&node_did)?;
    let cert_fingerprint = tls_identity.fingerprint.clone();

    info!("Node DID: {}", node_did);
    info!("Cert fingerprint: {}", cert_fingerprint);

    // ── Hydrate in-memory registry from DB ────────────────────────────────────
    let registry = Arc::new(Mutex::new(FederatedRegistry::new()));
    {
        let mut reg = registry.lock().unwrap();
        let agents = store.load_all_agents().await?;
        let agent_count = agents.len();
        for ad in agents {
            let _ = reg.register_local(ad);
        }
        let peers = store.load_all_peers().await?;
        let peer_count = peers.len();
        for peer in peers {
            reg.add_peer(peer);
        }
        info!("Hydrated registry: {} agents, {} peers", agent_count, peer_count);
    }

    let app_state = AppState::new(
        registry.clone(),
        store.clone(),
        node_did.clone(),
        &config,
        cert_fingerprint.clone(),
    );

    // ── Routers ───────────────────────────────────────────────────────────────

    // Federation protocol routes (PAP-compatible).
    let federation_router = FederationServer::new(
        registry.clone(),
        config.port,
        node_did,
        config.public_endpoint.clone(),
        cert_fingerprint,
    )
    .router();

    // Admin API routes.
    let admin_router = routes::admin::router().with_state(app_state);

    // Static file serving for the web UI.
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
    info!("Federation endpoint: http://{}/federation/identity", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
