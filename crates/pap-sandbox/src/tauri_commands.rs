//! Tauri IPC command handlers for pap-sandbox.
//!
//! These commands expose sandbox control to the Papillon frontend:
//! - Spawn a sandboxed agent execution
//! - Poll execution state
//! - Force-terminate a running execution
//! - Retrieve the attestation receipt
//! - Update capability policies

use serde_json::Value;
use tauri::State;

use crate::error::SandboxError;
use crate::ipc::ExecutionContext;
use crate::policy::CapabilityPolicy;
use crate::receipt::AttestationReceipt;
use crate::spawner::{AgentSpawner, ExecutionHandle, ExecutionState};

/// Shared sandbox state available to all Tauri commands.
pub struct SandboxCommandState {
    pub spawner: Box<dyn AgentSpawner>,
}

#[tauri::command]
pub async fn sandbox_spawn_execution(
    state: State<'_, SandboxCommandState>,
    context: ExecutionContext,
    policy: Option<CapabilityPolicy>,
) -> Result<ExecutionHandle, String> {
    let policy = policy.unwrap_or_default();
    state
        .spawner
        .spawn(policy, context)
        .await
        .map_err(|e: SandboxError| e.to_string())
}

#[tauri::command]
pub async fn sandbox_get_execution_state(
    state: State<'_, SandboxCommandState>,
    handle: ExecutionHandle,
) -> Result<ExecutionState, String> {
    state
        .spawner
        .poll_state(&handle)
        .await
        .map_err(|e: SandboxError| e.to_string())
}

#[tauri::command]
pub async fn sandbox_force_terminate(
    state: State<'_, SandboxCommandState>,
    handle: ExecutionHandle,
    reason: String,
) -> Result<Value, String> {
    state
        .spawner
        .terminate(&handle, &reason)
        .await
        .map_err(|e: SandboxError| e.to_string())?;
    Ok(serde_json::json!({ "success": true, "handle_id": handle.id }))
}

#[tauri::command]
pub async fn sandbox_get_receipt(
    state: State<'_, SandboxCommandState>,
    handle: ExecutionHandle,
) -> Result<AttestationReceipt, String> {
    let (_result, receipt) = state
        .spawner
        .collect_result(&handle)
        .await
        .map_err(|e: SandboxError| e.to_string())?;
    Ok(receipt)
}

#[tauri::command]
pub fn sandbox_default_policy() -> CapabilityPolicy {
    CapabilityPolicy::default()
}
