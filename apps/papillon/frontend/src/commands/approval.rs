use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Signed challenge for identity authorization.
/// Must match the backend SignedChallenge structure.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedChallenge {
    pub challenge_id: String,
    pub signature_b64: String,
}

/// Payload for the approval command.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPayload {
    pub approval_request_id: String,
    pub approved: bool,
    pub signed_challenge: SignedChallenge,
    pub filled_values: Option<HashMap<String, String>>,
    pub selected_agent_names: Option<Vec<String>>,
}

/// Call the backend approval command.
///
/// In desktop builds (Tauri), this invokes the `canvas_approve_block` command.
/// In WASM builds, this would call through the bridge (currently returning an error).
pub async fn approve_intent_plan(payload: ApprovalPayload) -> Result<(), String> {
    #[cfg(target_family = "wasm")]
    {
        crate::bridge::invoke("canvas_approve_block", &payload).await
    }

    #[cfg(not(target_family = "wasm"))]
    {
        let _ = payload; // Silence unused warning
        Err("approve_intent_plan is only available in Tauri builds".to_string())
    }
}
