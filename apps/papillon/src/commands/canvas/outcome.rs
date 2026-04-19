use sha2::{Digest, Sha256};
use tauri::State;

use crate::db::prelude::DatabaseOps;
use crate::error::PapillonError;
use crate::state::AppState;

use super::types::{CanvasSummaryState, EpisodeSummary};

/// Retrieve the current canvas outcome state.
///
/// Reads completed episodes from the persistent episode store and synthesises
/// a `CanvasSummaryState` for the frontend outcome timeline.  All data is
/// derived from the encrypted-at-rest SQLite DB — no in-memory session state
/// is required.
#[tauri::command]
pub fn get_canvas_state(state: State<'_, AppState>) -> Result<CanvasSummaryState, PapillonError> {
    // Get principal DID from the current signer
    let principal_did = {
        let signer = state
            .signer
            .read()
            .map_err(|e| PapillonError::from(e.to_string()))?;
        match signer.as_ref() {
            Some(s) => s.did(),
            None => "did:key:unknown".to_string(),
        }
    };

    // Load up to 100 most recent episodes from the persistent store
    let raw_episodes = state
        .db
        .list_episodes(None, None, 100, Some(0))
        .map_err(|e| PapillonError::from(e.0))?;

    let mut success_count: u32 = 0;
    let mut failure_count: u32 = 0;

    let episodes: Vec<EpisodeSummary> = raw_episodes
        .iter()
        .map(|ep| {
            // Derive a display-safe session identifier (first 16 chars)
            let session_did = if ep.receipt_session_id.len() > 16 {
                ep.receipt_session_id[..16].to_string()
            } else {
                ep.receipt_session_id.clone()
            };

            // Compute a stable receipt hash from the session ID
            let mut hasher = Sha256::new();
            hasher.update(ep.receipt_session_id.as_bytes());
            let receipt_hash = format!("{:x}", hasher.finalize());
            // Truncate to first 16 hex chars for display
            let receipt_hash = receipt_hash[..16].to_string();

            if ep.outcome == "success" {
                success_count += 1;
            } else {
                failure_count += 1;
            }

            EpisodeSummary {
                session_did,
                agent_did: ep.agent_did_hash.clone(),
                agent_name: ep.agent_name.clone(),
                action: ep.action_type.clone(),
                outcome: ep.outcome.clone(),
                timestamp: ep.recorded_at.clone(),
                receipt_hash,
                intent_summary: ep.intent_summary.clone(),
            }
        })
        .collect();

    Ok(CanvasSummaryState {
        principal_did,
        episodes,
        success_count,
        failure_count,
        active_sessions: 0,
    })
}
