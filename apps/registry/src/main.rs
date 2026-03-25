use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use leptos::config::get_configuration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing::info;

use pap_did::PrincipalKeypair;
use pap_federation::registry::FederatedRegistry;
use pap_federation::server::FederationServer;
use pap_registry::config::Config;
use pap_registry::db::{DbConfig, NodeIdentity, RegistryStore};
use pap_registry::routes;
use pap_registry::state::AppState;

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
    let db_cfg = DbConfig::resolve()?;
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
            info!(
                "Generated and persisted new node identity: {}",
                identity.did
            );
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
            if let Err(e) = reg.register_local(ad.clone()) {
                tracing::warn!("Skipping agent {} during hydration: {e}", ad.hash());
            }
        }
        let peers = store.load_all_peers().await?;
        let peer_count = peers.len();
        for peer in peers {
            reg.add_peer(peer);
        }
        info!(
            "Hydrated registry: {} agents, {} peers",
            agent_count, peer_count
        );
    }

    let app_state = AppState::new(
        registry.clone(),
        store.clone(),
        node_did.clone(),
        &config,
        cert_fingerprint.clone(),
    );

    // ── Leptos configuration ──────────────────────────────────────────────────
    let leptos_options = get_configuration(None).unwrap().leptos_options;

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
    let admin_router = routes::admin::router().with_state(app_state.clone());

    // Leptos SSR + hydration routes (replaces ServeDir fallback).
    let leptos_router = routes::leptos_handler::leptos_router(leptos_options.clone(), app_state)
        .with_state(leptos_options);

    // TODO(I9): allow_origin(Any) permits cross-origin Bearer-authenticated requests from any
    // web page. Acceptable for a reference implementation on a trusted network. For
    // production deployments that require strict origin isolation, restrict this to
    // the node's own public_endpoint origin and leave federation routes open separately.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Static assets (icon, favicon, logo).
    // Local dev: workspace root → apps/registry/assets
    // Docker:    /app → /app/assets  (set PAP_ASSETS_DIR=/app/assets)
    let assets_dir = std::env::var("PAP_ASSETS_DIR")
        .unwrap_or_else(|_| "apps/registry/assets".into());

    let app = Router::new()
        .merge(federation_router)
        .merge(admin_router)
        .nest_service("/assets", ServeDir::new(&assets_dir))
        .merge(leptos_router)
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("Registry running on http://{}", addr);
    info!("Admin UI available at http://{}/", addr);
    info!("Federation endpoint: http://{}/federation/identity", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
