use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("sequence error: expected {expected}, got {got}")]
    SequenceError { expected: u64, got: u64 },

    #[error("unknown session: {0}")]
    UnknownSession(String),

    #[error("invalid state transition: {from} -> {to}")]
    InvalidTransition { from: String, to: String },

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("session not open — DID exchange required before sending sealed messages")]
    SessionNotOpen,
}
