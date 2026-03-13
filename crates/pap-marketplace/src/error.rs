use thiserror::Error;

#[derive(Debug, Error)]
pub enum MarketplaceError {
    #[error("advertisement not found: {0}")]
    NotFound(String),

    #[error("invalid advertisement: {0}")]
    InvalidAdvertisement(String),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("registry error: {0}")]
    RegistryError(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}
