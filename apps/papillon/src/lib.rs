pub mod agents;
pub mod commands;
pub mod db;
pub mod discovery;
pub mod error;
pub mod handshake;
pub mod inference;
pub mod profiles_db;
pub mod state;

use std::net::SocketAddr;

use pap_did::PrincipalKeypair;
use pap_federation::{generate_node_identity, FederationServer};
use pap_transport::AgentServer;
use pap_webauthn::SoftwareSigner;
use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .setup(|app| {
            // Resolve data directory for persistent storage
            let data_dir = app
                .path()
                .app_data_dir()
                .expect("failed to resolve app data dir");
            std::fs::create_dir_all(&data_dir).expect("failed to create app data dir");
            let db_path = data_dir.join("papillon.db");

            // Resolve resource directory before creating AppState so we can pass
            // catalog_dir for first-run seeding.
            let resource_dir = app
                .path()
                .resource_dir()
                .expect("failed to resolve resource dir");
            let catalog_dir = resource_dir.join("catalog");

            // Create AppState with persistent database.
            // Identity is auto-loaded from SQLite or generated on first launch.
            let app_state = AppState::new(&db_path, catalog_dir);

            *app_state.resource_dir.write().unwrap() = resource_dir;
            *app_state.data_dir.write().unwrap() = data_dir.clone();

            // Clone state for the background federation server before manage() takes ownership.
            let state_clone = app_state.clone_for_background();

            // Run the retention reducer once at startup to clean up any accumulated episodes
            // from previous sessions, then hand off to a periodic background task.
            let retention_db = app_state.db.clone();
            std::thread::spawn(move || {
                use papillon_shared::db::DatabaseOps;
                // Initial pass — run immediately.
                match retention_db.apply_retention_policy() {
                    Ok(stats) if stats.compressed > 0 || stats.deleted > 0 => {
                        eprintln!(
                            "Retention reducer: compressed={}, deleted={}",
                            stats.compressed, stats.deleted
                        );
                    }
                    Err(e) => eprintln!("Retention reducer error: {e}"),
                    _ => {}
                }

                // Hourly pass — reduces unbounded episode growth over long sessions.
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                    match retention_db.apply_retention_policy() {
                        Ok(stats) if stats.compressed > 0 || stats.deleted > 0 => {
                            eprintln!(
                                "Retention reducer (hourly): compressed={}, deleted={}",
                                stats.compressed, stats.deleted
                            );
                        }
                        Err(e) => eprintln!("Retention reducer error: {e}"),
                        _ => {}
                    }
                }
            });

            app.manage(app_state);

            // Spawn federation server on a separate thread with its own tokio runtime.
            // This avoids blocking the Tauri main thread and provides the async context
            // that tokio::spawn() requires.
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
                rt.block_on(async {
                    if let Err(e) = start_federation_server_async(&state_clone).await {
                        eprintln!("Federation server startup error: {e}");
                    }
                });
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::health::get_health_status,
            commands::identity::create_identity,
            commands::identity::get_identity,
            commands::profiles::list_profiles,
            commands::profiles::create_profile,
            commands::profiles::switch_profile,
            commands::profiles::rename_profile,
            commands::profiles::delete_profile,
            commands::profiles::export_profile_seed,
            commands::profiles::import_profile_seed,
            commands::registry::navigate_registry,
            commands::registry::list_agents,
            commands::registry::search_agents,
            commands::registry::sync_agents,
            commands::registry::discover_peers,
            commands::registry::add_bookmark,
            commands::registry::remove_bookmark,
            commands::registry::list_bookmarks,
            commands::registry::get_node_addresses,
            commands::registry::register_agent,
            commands::registry::get_node_info,
            commands::orchestrator::get_orchestrator_config,
            commands::orchestrator::configure_orchestrator,
            commands::orchestrator::get_orchestrator_status,
            commands::orchestrator::get_setup_state,
            commands::orchestrator::list_scenarios,
            commands::orchestrator::run_scenario,
            commands::orchestrator::list_completed_runs,
            commands::orchestrator::list_agent_profiles,
            commands::llm::check_llm_connection,
            commands::orchestrator::list_builtin_models,
            commands::orchestrator::load_builtin_model,
            commands::orchestrator::check_model_availability,
            commands::orchestrator::download_builtin_model,
            commands::identity::export_key,
            commands::identity::import_key,
            commands::identity::get_key_backup_status,
            commands::identity::add_successor,
            commands::identity::list_successors,
            commands::identity::remove_successor,
            commands::canvas::canvas_prompt,
            commands::canvas::canvas_reshape,
            commands::canvas::canvas_retry,
            commands::pipeline::run_pipeline,
            commands::templates::get_global_templates,
            commands::templates::get_profile_templates,
            commands::templates::create_template,
            commands::templates::update_template,
            commands::templates::delete_template,
            commands::templates::set_template_enabled,
            commands::templates::export_templates,
            commands::templates::import_templates,
            commands::templates::auto_generate_template,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Papillon");
}

/// Start the combined TLS server for federation and agent endpoints.
///
/// Generates a self-signed TLS certificate bound to the node's DID,
/// builds a combined Axum router with federation + per-agent routes,
/// and spawns it on a background tokio task.
async fn start_federation_server_async(state: &AppState) -> Result<(), Box<dyn std::error::Error>> {
    // Recreate signer from seed in the background thread context
    {
        let mut signer = state.signer.write().unwrap();
        if signer.is_none() {
            let seed_lock = state.principal_seed.read().unwrap();
            let seed_ref = seed_lock.as_ref().ok_or("No principal seed available")?;
            let keypair = PrincipalKeypair::from_bytes(seed_ref)
                .map_err(|e| format!("Failed to recreate keypair from seed: {e}"))?;
            *signer = Some(Box::new(SoftwareSigner::from_keypair(keypair)));
        }
    }

    // Get the node's DID from the signer
    let node_did = {
        let signer = state.signer.read().unwrap();
        match signer.as_ref() {
            Some(s) => s.did(),
            None => return Err("No signer available — cannot start federation server".into()),
        }
    };

    // Generate the node's TLS identity (self-signed cert with DID in SAN)
    let identity = generate_node_identity(&node_did)
        .map_err(|e| format!("TLS identity generation failed: {e}"))?;

    // Store the cert fingerprint so other parts of the app can access it
    *state.node_cert_fingerprint.write().unwrap() = identity.fingerprint.clone();

    let port = state.federation_port;
    let endpoint = format!("https://0.0.0.0:{port}");
    *state.node_endpoint.write().unwrap() = endpoint.clone();

    // Build the combined router: federation routes + agent routes
    let registry = state.local_registry.clone();
    let federation_server = FederationServer::new(
        registry,
        port,
        node_did.clone(),
        endpoint,
        identity.fingerprint.clone(),
    );
    let mut router = federation_server.router();

    // Mount each local agent's handshake endpoints under /agents/{slug}/
    for (name, handler) in &state.local_agents {
        let agent_server = AgentServer::new(handler.clone(), 0);
        let slug = name.to_lowercase().replace(' ', "-");
        router = router.nest(&format!("/agents/{slug}"), agent_server.router());
    }

    // Build axum-server TLS config from the node identity
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(identity.server_config);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // Spawn the server on a background tokio task
    tokio::spawn(async move {
        if let Err(e) = axum_server::bind_rustls(addr, tls_config)
            .serve(router.into_make_service())
            .await
        {
            eprintln!("Federation server error: {e}");
        }
    });

    // Discover LAN addresses and store as pap:// URLs for the Settings UI
    {
        let pap_urls: Vec<String> = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .filter(|iface| !iface.is_loopback())
            .filter_map(|iface| {
                if let if_addrs::IfAddr::V4(ref addr) = iface.addr {
                    Some(format!("pap://{}:{}", addr.ip, port))
                } else {
                    None
                }
            })
            .collect();
        *state.local_pap_urls.write().unwrap() = pap_urls;
    }

    // Spawn background discovery loop
    let discovery_registry = state.local_registry.clone();
    tokio::spawn(async move {
        discovery::run_discovery_loop(discovery_registry).await;
    });

    eprintln!(
        "PAP federation node started on port {port} (TLS, fingerprint: {})",
        identity.fingerprint
    );

    Ok(())
}
