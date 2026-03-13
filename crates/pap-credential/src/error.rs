use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("disclosure error: {0}")]
    DisclosureError(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("expired credential")]
    Expired,
}
