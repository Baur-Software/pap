pub mod agents;
pub mod commands;
pub mod db;
pub mod discovery;
pub mod error;
pub mod handshake;
pub mod inference;
pub mod seed;
pub mod state;

use std::net::SocketAddr;

use pap_federation::{generate_node_identity, FederationServer};
use pap_transport::AgentServer;
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
            let db_path = data_dir.join("papillion.db");

            // Create AppState with persistent database.
            // Identity is auto-loaded from SQLite or generated on first launch.
            let app_state = AppState::new(&db_path);

            let resource_dir = app
                .path()
                .resource_dir()
                .expect("failed to resolve resource dir");
            *app_state.resource_dir.write().unwrap() = resource_dir;

            app.manage(app_state);

            // --- Start the TLS federation + agent server ---
            start_federation_server(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::identity::create_identity,
            commands::identity::get_identity,
            commands::registry::navigate_registry,
            commands::registry::list_agents,
            commands::registry::search_agents,
            commands::registry::sync_agents,
            commands::registry::discover_peers,
            commands::registry::add_bookmark,
            commands::registry::list_bookmarks,
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
            commands::identity::export_key,
            commands::identity::import_key,
            commands::identity::get_key_backup_status,
            commands::identity::add_successor,
            commands::identity::list_successors,
            commands::identity::remove_successor,
            commands::canvas::canvas_prompt,
            commands::canvas::canvas_reshape,
            commands::canvas::canvas_retry,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Papillion");
}

/// Start the combined TLS server for federation and agent endpoints.
///
/// Generates a self-signed TLS certificate bound to the node's DID,
/// builds a combined Axum router with federation + per-agent routes,
/// and spawns it on a background tokio task.
fn start_federation_server(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let state = app.state::<AppState>();

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
