#![allow(clippy::unwrap_used)]
pub mod agents;
pub mod challenge_store;
pub mod commands;
pub mod db;
pub mod discovery;
pub mod episode_store;
pub mod error;
pub mod handshake;
pub mod inference;
pub mod keypair_store;
pub mod profiles_db;
pub mod state;

use std::sync::atomic::Ordering;

use pap_sandbox::tauri_commands as sandbox_commands;
use pap_sandbox::tauri_commands::SandboxCommandState;

use episode_store::EpisodeStore;
use keypair_store::KeypairStore;
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

            // Dev-mode fallback: when running via `cargo tauri dev` the resource
            // bundle hasn't been assembled yet, so fall back to the workspace path.
            let catalog_dir = if catalog_dir.exists() {
                eprintln!("INFO papillon: catalog at {}", catalog_dir.display());
                catalog_dir
            } else {
                let ws_catalog = std::env::var("CARGO_MANIFEST_DIR")
                    .map(|d| {
                        std::path::PathBuf::from(d)
                            .join("../..")
                            .join("crates/pap-agents/catalog")
                    })
                    .unwrap_or_default();
                if ws_catalog.exists() {
                    eprintln!(
                        "INFO papillon: catalog not in resources, using workspace path {}",
                        ws_catalog.display()
                    );
                    ws_catalog
                } else {
                    eprintln!(
                        "WARN papillon: catalog not found at {} — agents will not be seeded",
                        catalog_dir.display()
                    );
                    catalog_dir
                }
            };

            // Open (or create) the persistent principal keypair store.
            // The 32-byte Ed25519 seed is stored as `principal.key` with mode
            // 0600 and zeroized in memory on drop.
            let keypair_store =
                KeypairStore::open(&data_dir).expect("failed to open principal keypair store");

            // Create AppState with persistent database.
            // Identity is auto-loaded from SQLite or generated on first launch.
            let app_state = AppState::new(&db_path, catalog_dir);

            *app_state
                .resource_dir
                .write()
                .unwrap_or_else(|e| e.into_inner()) = resource_dir;
            *app_state
                .data_dir
                .write()
                .unwrap_or_else(|e| e.into_inner()) = data_dir.clone();

            // Register the keypair store so Tauri commands can access it.
            app.manage(keypair_store);

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

            // Build the episode store from the same Arc<Database> used by AppState
            // so that both handles share the same rusqlite connection and schema.
            let episode_store = EpisodeStore::from_db(app_state.db.clone());
            app.manage(episode_store);

            app.manage(app_state);

            // Register the platform-appropriate sandbox spawner.
            // Detects OS capabilities, Docker, or falls back to unsandboxed execution.
            // Tauri 2's setup closure is sync; use Handle::try_current() to reuse
            // an existing runtime if present, otherwise create a temporary one.
            let sandbox_state = {
                let rt = tokio::runtime::Runtime::new()
                    .expect("failed to create tokio runtime for sandbox init");
                match rt.block_on(pap_sandbox::new_spawner()) {
                    Ok(spawner) => SandboxCommandState { spawner },
                    Err(e) => {
                        eprintln!("WARN papillon: pap-sandbox unavailable on this platform — {e}");
                        SandboxCommandState {
                            spawner: Box::new(pap_sandbox::spawner::NoopSpawner),
                        }
                    }
                }
            };
            app.manage(sandbox_state);

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
            commands::identity::get_identity_challenge,
            commands::identity::sign_approval_challenge,
            commands::identity::create_identity,
            commands::identity::get_identity,
            commands::identity::get_principal_did,
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
            commands::orchestrator::list_episodes,
            commands::orchestrator::list_agent_profiles,
            commands::episodes::record_episode,
            commands::episodes::list_recent_episodes,
            commands::episodes::get_episode,
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
            commands::recovery::create_recovery_shards,
            commands::recovery::reconstruct_from_shards,
            commands::recovery::mark_recovery_complete,
            commands::recovery::get_recovery_status,
            commands::canvas::canvas_prompt,
            commands::canvas::canvas_reshape,
            commands::canvas::canvas_retry,
            commands::canvas::canvas_plan_prompt,
            commands::canvas::canvas_approve_block,
            commands::canvas::canvas_list,
            commands::canvas::canvas_create,
            commands::canvas::canvas_delete,
            commands::canvas::canvas_rename,
            commands::canvas::canvas_block_create,
            commands::canvas::canvas_block_resolve,
            commands::canvas::canvas_block_fail,
            commands::canvas::canvas_block_delete,
            commands::canvas::canvas_blocks_load,
            commands::canvas::canvas_message_add,
            commands::canvas::canvas_messages_load,
            commands::canvas::canvas_generate_guide,
            commands::canvas::canvas_create_note,
            commands::canvas::canvas_update_note,
            commands::canvas::canvas_delete_note,
            commands::dataset_discovery::canvas_discover_datasets,
            commands::dataset_discovery::list_dataset_agents,
            commands::pipeline::run_pipeline,
            commands::pipeline::save_pipeline,
            commands::pipeline::list_saved_pipelines,
            commands::pipeline::delete_saved_pipeline,
            commands::pipeline::run_saved_pipeline,
            commands::pipeline::port_compatible,
            commands::pipeline::store_approval_record,
            commands::pipeline::discover_pap_agents,
            commands::templates::get_global_templates,
            commands::templates::get_profile_templates,
            commands::templates::create_template,
            commands::templates::update_template,
            commands::templates::delete_template,
            commands::templates::set_template_enabled,
            commands::templates::export_templates,
            commands::templates::import_templates,
            commands::templates::get_templates_for_type,
            commands::templates::auto_generate_template,
            commands::agents::list_local_agents,
            commands::agents::save_agent,
            commands::agents::delete_agent,
            commands::agents::update_agent,
            commands::agents::generate_agent,
            commands::agents::publish_agent,
            commands::agents::unpublish_agent,
            commands::agents::save_trait_beacon_profile,
            commands::agents::approve_federation_agent,
            commands::webauthn::begin_registration,
            commands::webauthn::complete_registration,
            commands::webauthn::begin_authentication,
            commands::webauthn::complete_authentication,
            commands::settings_vocab::get_settings_vocabulary,
            commands::settings_vocab::apply_setting,
            commands::canvas::get_canvas_state,
            commands::chat::list_conversations,
            commands::chat::get_chat_history,
            commands::chat::create_group_chat,
            commands::chat::join_group_chat,
            commands::chat::record_chat_message,
            commands::chat::mark_message_delivered,
            sandbox_commands::sandbox_spawn_execution,
            sandbox_commands::sandbox_get_execution_state,
            sandbox_commands::sandbox_force_terminate,
            sandbox_commands::sandbox_get_receipt,
            sandbox_commands::sandbox_default_policy,
            commands::vault::vault_open,
            commands::vault::vault_seal,
            commands::vault::vault_disclose_for_agent,
            commands::vault::vault_store_credential,
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
        let mut signer = state.signer.write().unwrap_or_else(|e| e.into_inner());
        if signer.is_none() {
            let seed_lock = state
                .principal_seed
                .read()
                .unwrap_or_else(|e| e.into_inner());
            let seed_ref = seed_lock.as_ref().ok_or("No principal seed available")?;
            let keypair = PrincipalKeypair::from_bytes(seed_ref)
                .map_err(|e| format!("Failed to recreate keypair from seed: {e}"))?;
            *signer = Some(Box::new(SoftwareSigner::from_keypair(keypair)));
        }
    }

    // Get the node's DID from the signer
    let node_did = {
        let signer = state.signer.read().unwrap_or_else(|e| e.into_inner());
        match signer.as_ref() {
            Some(s) => s.did(),
            None => return Err("No signer available — cannot start federation server".into()),
        }
    };

    // Generate the node's TLS identity (self-signed cert with DID in SAN)
    let identity = generate_node_identity(&node_did)
        .map_err(|e| format!("TLS identity generation failed: {e}"))?;

    // Store the cert fingerprint so other parts of the app can access it
    *state
        .node_cert_fingerprint
        .write()
        .unwrap_or_else(|e| e.into_inner()) = identity.fingerprint.clone();

    // Bind to port 0 so the OS assigns a free ephemeral port — no collisions
    // with Chrysalis (7890) or any other service on the machine.
    let listener = std::net::TcpListener::bind("0.0.0.0:0")
        .map_err(|e| format!("Failed to bind federation server socket: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to read bound port: {e}"))?
        .port();

    // Persist the actual port so other parts of the app (and clones) can read it
    state.federation_port.store(port, Ordering::Relaxed);

    let endpoint = format!("https://0.0.0.0:{port}");
    *state
        .node_endpoint
        .write()
        .unwrap_or_else(|e| e.into_inner()) = endpoint.clone();

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

    // Spawn the server on a background tokio task using the already-bound listener
    tokio::spawn(async move {
        match axum_server::from_tcp_rustls(listener, tls_config) {
            Ok(server) => {
                if let Err(e) = server.serve(router.into_make_service()).await {
                    eprintln!("Federation server error: {e}");
                }
            }
            Err(e) => eprintln!("Federation server bind error: {e}"),
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
        *state
            .local_pap_urls
            .write()
            .unwrap_or_else(|e| e.into_inner()) = pap_urls;
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
