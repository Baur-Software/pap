use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("signing failed: {0}")]
    SigningFailed(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid credential: {0}")]
    InvalidCredential(String),

    #[error("ceremony failed: {0}")]
    CeremonyFailed(String),

    #[error("challenge mismatch")]
    ChallengeMismatch,
}
