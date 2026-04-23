#![allow(clippy::unwrap_used)]
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Context as _;

use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::Router;
use leptos::config::get_configuration;
use pap_registry::state::SETTING_CORS_ORIGINS;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

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

/// Validate the authentication configuration at startup.
///
/// - If `admin_token` is `None`, emit a prominent `WARN` so operators notice
///   immediately in logs.
/// - If `require_auth` is also `true`, bail out so the server refuses to start
///   without a configured token (useful in hardened / production deployments).
fn check_auth_config(config: &Config) -> anyhow::Result<()> {
    if config.admin_token.is_none() {
        tracing::warn!(
            "⚠️  PAP_REGISTRY_ADMIN_TOKEN is not set — all admin endpoints are UNAUTHENTICATED. \
             In production, set PAP_REGISTRY_ADMIN_TOKEN to a strong random secret. \
             Set PAP_REGISTRY_REQUIRE_AUTH=true to refuse startup without a token."
        );
        if config.require_auth {
            anyhow::bail!(
                "PAP_REGISTRY_REQUIRE_AUTH=true but PAP_REGISTRY_ADMIN_TOKEN is not set. \
                 Provide a token via PAP_REGISTRY_ADMIN_TOKEN or unset PAP_REGISTRY_REQUIRE_AUTH."
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("pap_registry=info".parse().unwrap()),
        )
        .init();

    let config = Config::from_env();
    check_auth_config(&config)?;

    info!("Starting PAP Registry on {}:{}", config.host, config.port);

    // ── Database setup ────────────────────────────────────────────────────────
    let db_cfg = DbConfig::resolve()?;

    // PAP_REGISTRY_RESET_DB=true: wipe the SQLite file so migrations start
    // from a clean slate.  Use this to recover from "migration was previously
    // applied but has been modified" errors during development.
    if config.reset_db {
        if let Some(path) = db_cfg.sqlite_file_path() {
            if std::path::Path::new(&path).exists() {
                tracing::warn!(
                    "PAP_REGISTRY_RESET_DB=true — deleting existing database at {path}. \
                     All agents, peers, and node identity will be regenerated."
                );
                std::fs::remove_file(&path)
                    .with_context(|| format!("Failed to delete database file at {path}"))?;
            }
        }
    }

    let store = RegistryStore::connect(&db_cfg).await?;
    store.migrate().await.map_err(|e| {
        // Surface a clear recovery hint when the migration checksum mismatches —
        // the most common cause is a volume created with an older schema.
        if e.to_string()
            .contains("previously applied but has been modified")
        {
            anyhow::anyhow!(
                "{e}\n\n\
                 HINT: The on-disk database was created with an earlier version of the schema.\n\
                 To recover, restart the registry with PAP_REGISTRY_RESET_DB=true (this will \
                 delete all stored data and regenerate the node identity)."
            )
        } else {
            e
        }
    })?;
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

            // Seed TOML catalog agents when PAP_CATALOG_PATH is configured.
            if let Ok(catalog_env) = std::env::var("PAP_CATALOG_PATH") {
                let catalog_path = std::path::PathBuf::from(&catalog_env);
                if catalog_path.exists() {
                    let catalog_defs = pap_agents::load_catalog(&catalog_path);
                    let mut catalog_seeded = 0usize;
                    for def in &catalog_defs {
                        match def.to_signed_advertisement() {
                            Ok(ad) => {
                                let hash = ad.hash();
                                if store.insert_agent(&hash, &ad).await.is_ok() {
                                    persisted.push(ad);
                                    catalog_seeded += 1;
                                }
                            }
                            Err(e) => tracing::warn!("Startup catalog sign error: {e}"),
                        }
                    }
                    info!(
                        "Seeded {} TOML catalog agents from {}",
                        catalog_seeded, catalog_env
                    );
                } else {
                    tracing::warn!(
                        "PAP_CATALOG_PATH={catalog_env} does not exist; skipping TOML catalog seeding"
                    );
                }
            }

            persisted
        } else {
            vec![]
        };

        // Now acquire the lock for synchronous in-memory registration only.
        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
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

    // ── CORS allowlist — loaded from DB, seeded from config on first boot ────
    // `ALLOWED_ORIGINS` env var overrides the DB value at startup. Useful in
    // CI / container environments where the admin UI is not yet configured.
    // Set to `"*"` for open access (e.g. tests) or a comma-separated list of
    // exact origins for production.
    let cors_origins_raw = if let Ok(env_origins) = std::env::var("ALLOWED_ORIGINS") {
        if !env_origins.is_empty() {
            info!("CORS: using ALLOWED_ORIGINS env override: {}", env_origins);
            env_origins
        } else {
            let default = config.default_cors_origins();
            info!(
                "CORS: ALLOWED_ORIGINS empty, seeding from config: {}",
                default
            );
            default
        }
    } else {
        match store.load_setting(SETTING_CORS_ORIGINS).await? {
            Some(v) if !v.is_empty() => v,
            _ => {
                let default = config.default_cors_origins();
                store.save_setting(SETTING_CORS_ORIGINS, &default).await?;
                info!("CORS: seeded allowed origins from config: {}", default);
                default
            }
        }
    };
    let cors_origins: Vec<String> = cors_origins_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    info!("CORS: allowed origins = {:?}", cors_origins);
    let cors_allowed_origins: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(cors_origins));

    let app_state = AppState::new(
        registry.clone(),
        store.clone(),
        node_did.clone(),
        &config,
        cert_fingerprint.clone(),
        cors_allowed_origins.clone(),
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

    // CORS policy — build the layer from the current allowlist. If the list
    // contains `"*"` respond with `Access-Control-Allow-Origin: *` via
    // `Any`; otherwise use a per-request predicate that echoes back the
    // exact origin for strict allowlist enforcement. The live `Arc<RwLock>`
    // means changes saved via the admin Settings UI take effect immediately.
    let cors = {
        let list = cors_allowed_origins
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if list.iter().any(|o| o == "*") {
            info!("CORS: open policy (*)");
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        } else {
            let origins_ref = cors_allowed_origins.clone();
            let allow_origin = AllowOrigin::predicate(move |origin, _req| {
                let list = origins_ref.read().unwrap_or_else(|e| e.into_inner());
                list.iter()
                    .any(|allowed| origin.as_bytes() == allowed.as_bytes())
            });
            CorsLayer::new()
                .allow_origin(allow_origin)
                .allow_methods(Any)
                .allow_headers(Any)
        }
    };

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
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Env-var tests must run serially to avoid races.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_auth_env() {
        env::remove_var("PAP_REGISTRY_REQUIRE_AUTH");
        env::remove_var("PAP_REGISTRY_ADMIN_TOKEN");
    }

    #[test]
    fn require_auth_without_token_returns_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        env::set_var("PAP_REGISTRY_REQUIRE_AUTH", "true");

        let cfg = Config::from_env();
        let result = check_auth_config(&cfg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("PAP_REGISTRY_ADMIN_TOKEN"));

        clear_auth_env();
    }

    #[test]
    fn require_auth_with_token_is_ok() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        env::set_var("PAP_REGISTRY_REQUIRE_AUTH", "true");
        env::set_var("PAP_REGISTRY_ADMIN_TOKEN", "supersecret");

        let cfg = Config::from_env();
        assert!(check_auth_config(&cfg).is_ok());

        clear_auth_env();
    }

    #[test]
    fn no_require_auth_no_token_is_ok() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_auth_env();

        let cfg = Config::from_env();
        // Should not error — just warn at runtime.
        assert!(check_auth_config(&cfg).is_ok());
    }
}
