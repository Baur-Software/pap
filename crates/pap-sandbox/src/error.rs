use thiserror::Error;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("execution timeout after {0}s")]
    Timeout(u64),

    #[error("capability enforcement failed: {0}")]
    CapabilityError(String),

    #[error("IPC channel error: {0}")]
    IpcError(String),

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("memory protection failed: {0}")]
    MemoryError(String),

    #[error("platform unsupported: {0}")]
    PlatformUnsupported(String),

    #[error("process spawn failed: {0}")]
    SpawnError(String),

    #[error("process not found: {0}")]
    ProcessNotFound(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

impl From<SandboxError> for pap_transport::TransportError {
    fn from(e: SandboxError) -> Self {
        pap_transport::TransportError::ServerError(e.to_string())
    }
}

impl From<serde_json::Error> for SandboxError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}
