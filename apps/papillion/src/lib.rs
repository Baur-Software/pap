pub mod commands;
pub mod error;
pub mod inference;
pub mod seed;
pub mod state;

use pap_did::PrincipalKeypair;
use pap_webauthn::SoftwareSigner;
use state::AppState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState::default();

    // Auto-create a principal identity on first launch so the app is
    // immediately usable without requiring a manual setup step.
    {
        let mut signer = app_state.signer.write().unwrap();
        if signer.is_none() {
            let keypair = PrincipalKeypair::generate();
            let raw_seed = keypair.signing_key().to_bytes();
            *signer = Some(Box::new(SoftwareSigner::from_keypair(keypair)));
            drop(signer);
            let mut seed = app_state.principal_seed.write().unwrap();
            *seed = Some(raw_seed);
        }
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .manage(app_state)
        .setup(|app| {
            let resource_dir = app
                .path()
                .resource_dir()
                .expect("failed to resolve resource dir");
            let state = app.state::<AppState>();
            *state.resource_dir.write().unwrap() = resource_dir;
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
            commands::orchestrator::get_orchestrator_config,
            commands::orchestrator::configure_orchestrator,
            commands::orchestrator::get_orchestrator_status,
            commands::orchestrator::get_setup_state,
            commands::orchestrator::list_scenarios,
            commands::orchestrator::run_scenario,
            commands::orchestrator::list_completed_runs,
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
