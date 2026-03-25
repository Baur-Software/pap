//! TEE-specific error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TeeError {
    #[error("invalid measurement encoding: {0}")]
    InvalidMeasurement(String),

    #[error("invalid attestation report encoding: {0}")]
    InvalidReport(String),

    #[error("attestation nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: String, got: String },

    #[error("attestation expired (older than {max_age_secs}s)")]
    AttestationExpired { max_age_secs: u64 },

    #[error("untrusted enclave measurement: {0}")]
    UntrustedMeasurement(String),

    #[error("attestation report verification failed: {0}")]
    VerificationFailed(String),
}
