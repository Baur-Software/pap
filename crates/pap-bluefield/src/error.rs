use thiserror::Error;

#[derive(Debug, Error)]
pub enum BluefieldError {
    // ── RDMA device / resource errors ─────────────────────────────────────
    #[error("no RDMA device found: {0}")]
    DeviceNotFound(String),

    #[error("RDMA device open failed: {0}")]
    DeviceOpenFailed(String),

    #[error("RDMA resource allocation failed: {0}")]
    AllocationFailed(String),

    #[error("RDMA queue-pair state transition failed: {0}")]
    QpTransitionFailed(String),

    #[error("RDMA work-completion error (status={0})")]
    WorkCompletionError(u32),

    #[error("RDMA error: {0}")]
    RdmaError(String),

    // ── Bootstrap / connection errors ─────────────────────────────────────
    #[error("bootstrap failed: {0}")]
    BootstrapFailed(String),

    // ── Protocol framing errors ───────────────────────────────────────────
    #[error("message too large: {0} bytes")]
    MessageTooLarge(usize),

    #[error("frame truncated: {0}")]
    FrameTruncated(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    // ── Passthrough errors ────────────────────────────────────────────────
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("transport error: {0}")]
    Transport(#[from] pap_transport::TransportError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
