use thiserror::Error;

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("peer unreachable: {0}")]
    PeerUnreachable(String),

    #[error("invalid advertisement: {0}")]
    InvalidAdvertisement(String),

    #[error("duplicate advertisement: {0}")]
    DuplicateAdvertisement(String),

    #[error("sync failed: {0}")]
    SyncFailed(String),

    #[error("server error: {0}")]
    ServerError(String),
}
