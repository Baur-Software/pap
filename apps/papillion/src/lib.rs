pub mod commands;
pub mod error;
pub mod inference;
#[cfg(any(test, feature = "demo"))]
pub mod seed;
pub mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .manage(AppState::default())
        .setup(|app| {
            commands::orchestrator::load_persisted_runs(app.handle());
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
            commands::orchestrator::run_demo_scenario,
            commands::orchestrator::run_agent_session,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running Papillion");
}
