pub mod commands;
pub mod error;
pub mod seed;
pub mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::default().build())
        .manage(AppState::default())
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running Papillion");
}
