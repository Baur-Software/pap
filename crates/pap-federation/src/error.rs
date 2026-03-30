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

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("notary error: {0}")]
    NotaryError(String),

    #[error("revocation error: {0}")]
    RevocationError(String),

    #[error("insufficient vouches: need {needed}, got {got}")]
    InsufficientVouches { needed: usize, got: usize },

    #[error("voucher too young: {did} (age {age_days} days, minimum {min_days} days)")]
    VoucherTooYoung {
        did: String,
        age_days: u64,
        min_days: u64,
    },

    #[error("invalid vouch: {0}")]
    InvalidVouch(String),

    #[error("voucher not found: {0}")]
    VoucherNotFound(String),

    #[error("peer is probationary and cannot vouch: {0}")]
    PeerProbationary(String),
}
