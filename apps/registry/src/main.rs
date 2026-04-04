use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::routing::get;
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
use pap_transport::server::AgentServer;

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

    // TLS cert is ephemeral — bound to the (now stable) DID.
    // Skipped entirely in no-TLS mode.
    let (tls_identity, cert_fingerprint) = if config.no_tls {
        (None, String::new())
    } else {
        let id = pap_federation::generate_node_identity(&node_did)?;
        let fp = id.fingerprint.clone();
        (Some(id), fp)
    };

    info!("Node DID: {}", node_did);
    if !cert_fingerprint.is_empty() {
        info!("Cert fingerprint: {}", cert_fingerprint);
    }

    // Build agent set once — used for both DB seeding and execution routing.
    // A single build ensures the advertised DIDs match the execution handler DIDs.
    let agent_set = pap_agents::build_agents(vec![]);
    info!(
        "Built {} agent handlers for execution",
        agent_set.handlers.len()
    );

    // ── Hydrate in-memory registry from DB ────────────────────────────────────
    // Do all async DB work before acquiring the Mutex to avoid holding a
    // MutexGuard across await points (clippy::await_holding_lock).
    let registry = Arc::new(Mutex::new(FederatedRegistry::new()));
    {
        let agents = store.load_all_agents().await?;
        let agent_count = agents.len();
        let peers = store.load_all_peers().await?;
        let peer_count = peers.len();

        // Seed standard agents on first boot — async writes happen before the lock.
        let seeded_ads: Vec<_> = if agent_count == 0 {
            let seed_ads = agent_set.registry.all_advertisements().to_vec();
            let seed_count = seed_ads.len();
            let mut persisted = Vec::with_capacity(seed_count);
            for ad in seed_ads {
                let hash = ad.hash();
                if let Err(e) = store.insert_agent(&hash, &ad).await {
                    tracing::warn!("Failed to seed agent {}: {e}", ad.name);
                } else {
                    persisted.push(ad);
                }
            }
            info!("Seeded registry with {} standard agents", persisted.len());
            persisted
        } else {
            vec![]
        };

        // Now acquire the lock for synchronous in-memory registration only.
        let mut reg = registry.lock().unwrap();
        for ad in agents {
            if let Err(e) = reg.register_local(ad.clone()) {
                tracing::warn!("Skipping agent {} during hydration: {e}", ad.hash());
            }
        }
        for peer in peers {
            reg.add_peer(peer);
        }
        for ad in seeded_ads {
            if let Err(e) = reg.register_local(ad.clone()) {
                tracing::warn!("Failed to register seeded agent {}: {e}", ad.name);
            }
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
    let assets_dir =
        std::env::var("PAP_ASSETS_DIR").unwrap_or_else(|_| "apps/registry/assets".into());

    // CSS: cargo-leptos writes to target/site/pkg/pap-registry-ui.css.
    // When running via plain `cargo run` that file doesn't exist, so fall
    // back to the source stylesheet at apps/registry/styles/main.css.
    let css_path = {
        let leptos_css = std::path::PathBuf::from("target/site/pkg/pap-registry-ui.css");
        if leptos_css.exists() {
            leptos_css
        } else {
            std::path::PathBuf::from("apps/registry/styles/main.css")
        }
    };
    info!("Serving CSS from {}", css_path.display());

    // Mount each agent's PAP handshake endpoints under /agents/{slug}/
    let mut agent_router = Router::new();
    for (name, handler) in &agent_set.handlers {
        let agent_server = AgentServer::new(handler.clone(), 0);
        let slug = name.to_lowercase().replace(' ', "-");
        agent_router = agent_router.nest(&format!("/agents/{slug}"), agent_server.router());
    }
    info!(
        "Mounted {} agent execution endpoints under /agents/",
        agent_set.handlers.len()
    );

    let app = Router::new()
        .merge(federation_router)
        .merge(admin_router)
        .merge(agent_router)
        .route(
            "/pkg/pap-registry-ui.css",
            get(move || {
                let path = css_path.clone();
                async move {
                    match tokio::fs::read(&path).await {
                        Ok(bytes) => axum::response::Response::builder()
                            .header("content-type", "text/css")
                            .body(axum::body::Body::from(bytes))
                            .unwrap(),
                        Err(_) => axum::response::Response::builder()
                            .status(404)
                            .body(axum::body::Body::empty())
                            .unwrap(),
                    }
                }
            }),
        )
        .nest_service("/assets", ServeDir::new(&assets_dir))
        .merge(leptos_router)
        .layer(cors);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let scheme = if config.no_tls { "http" } else { "https" };
    info!("Registry running on {scheme}://{addr}");
    info!("Admin UI available at {scheme}://{addr}/");
    info!("Federation endpoint: {scheme}://{addr}/federation/identity");

    if let Some(tls_id) = tls_identity {
        // Serve over HTTPS using the node's self-signed TLS certificate.
        // Papillon clients connect via TOFU (Trust On First Use) and pin
        // the cert fingerprint for subsequent connections.
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(tls_id.server_config);
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    } else {
        // Plain HTTP — for local development only.
        info!("TLS disabled (PAP_REGISTRY_NO_TLS=true)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}
