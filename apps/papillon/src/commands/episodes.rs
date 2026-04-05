//! Tauri commands for episode persistence via `EpisodeStore`.
//!
//! These commands expose the three core operations required by ISS-627:
//! - `record_episode` — write a completed agent run to SQLite
//! - `list_recent_episodes` — page the episode log for the frontend
//! - `get_episode` — fetch a single episode by UUID
//!
//! Each command takes `State<'_, EpisodeStore>` rather than the monolithic
//! `AppState` so the episode sub-system remains independently testable and
//! follows the single-responsibility principle.

use tauri::State;

use crate::db::Episode;
use crate::episode_store::EpisodeStore;

/// Record a completed agent run to the SQLite episode store.
///
/// The frontend (or other Tauri commands) call this after every scenario
/// execution to persist the run so it survives app restarts.
#[tauri::command]
pub fn record_episode(store: State<'_, EpisodeStore>, episode: Episode) -> Result<(), String> {
    store.record(&episode).map_err(|e| e.message)
}

/// Return the `limit` most-recent episodes, newest first.
///
/// `limit` is clamped to 200 to avoid sending huge payloads to the frontend.
/// Use the offset-based `list_episodes` orchestrator command for full
/// pagination if needed.
#[tauri::command]
pub fn list_recent_episodes(
    store: State<'_, EpisodeStore>,
    limit: Option<usize>,
) -> Result<Vec<Episode>, String> {
    let limit = limit.unwrap_or(50).min(200);
    store.list_recent(limit).map_err(|e| e.message)
}

/// Fetch a single episode by its UUID string.
///
/// Returns `null` (serialized as `None`) when no matching episode is found
/// rather than an error, so the frontend can handle the missing-id case
/// gracefully without try/catch.
#[tauri::command]
pub fn get_episode(store: State<'_, EpisodeStore>, id: String) -> Result<Option<Episode>, String> {
    store.get_by_id(&id).map_err(|e| e.message)
}
