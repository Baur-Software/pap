use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("request failed: {0}")]
    RequestFailed(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("handler error: {0}")]
    HandlerError(String),

    #[error("server error: {0}")]
    ServerError(String),

    #[error("WebSocket error: {0}")]
    WebSocketError(String),

    #[error("protocol error: {0}")]
    ProtoError(#[from] pap_proto::ProtoError),

    #[error("OHTTP encryption failed: {0}")]
    OhttpEncryptionFailed(String),

    #[error("OHTTP decryption failed: {0}")]
    OhttpDecryptionFailed(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}
