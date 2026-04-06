//! Error types for the pap-ecash crate.

/// Errors produced by Chaumian ecash operations.
#[derive(Debug, thiserror::Error)]
pub enum EcashError {
    /// Blind signature operation failed (key generation, blinding, signing, or finalisation).
    #[error("blind signature error: {0}")]
    BlindSignature(String),

    /// Token serial has already been recorded in the spent registry.
    #[error("ecash double spend: serial already redeemed")]
    DoubleSpend,

    /// Signature verification failed (token is invalid or was tampered with).
    #[error("ecash verification failed")]
    VerificationFailed,

    /// PEM encoding or decoding error.
    #[error("pem error: {0}")]
    Pem(String),
}
