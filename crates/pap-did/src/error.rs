use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("invalid DID format: {0}")]
    InvalidDid(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}
