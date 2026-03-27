use serde::{Deserialize, Serialize};

/// Emitted during 6-phase handshake progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeProgressEvent {
    pub session_id: String,
    pub phase: u8,
    pub phase_name: String,
    pub status: String,
}

/// Emitted when a registry sync completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySyncedEvent {
    pub url: String,
    pub agent_count: usize,
}

/// Emitted when a session state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStateEvent {
    pub session_id: String,
    pub old_state: String,
    pub new_state: String,
}

/// Emitted during pipeline execution for each step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStepEvent {
    pub pipeline_id: String,
    pub step: usize,
    pub total: usize,
    pub node_id: String,
    pub status: String,
}
