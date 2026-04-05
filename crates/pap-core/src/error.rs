use thiserror::Error;

#[derive(Debug, Error)]
pub enum PapError {
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    #[error("mandate error: {0}")]
    MandateError(String),

    #[error("delegation exceeds parent scope")]
    DelegationExceedsScope,

    #[error("delegation exceeds parent TTL")]
    DelegationExceedsTtl,

    #[error("mandate chain verification failed: {0}")]
    ChainVerificationFailed(String),

    #[error("mandate expired")]
    MandateExpired,

    #[error("invalid decay state transition: {0} -> {1}")]
    InvalidDecayTransition(String, String),

    #[error("session error: {0}")]
    SessionError(String),

    #[error("invalid session state transition: {0} -> {1}")]
    InvalidSessionTransition(String, String),

    #[error("capability token error: {0}")]
    TokenError(String),

    #[error("nonce already consumed")]
    NonceConsumed,

    #[error("token target DID mismatch")]
    TokenTargetMismatch,

    #[error("receipt error: {0}")]
    ReceiptError(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("auto-approval policy exceeds mandate scope")]
    PolicyExceedsMandate,

    #[error("payment proof error: {0}")]
    PaymentProofError(String),

    #[error("missing payment proof: scope includes payment action but mandate has no proof")]
    MissingPaymentProof,

    #[error("recovery error: {0}")]
    RecoveryError(String),

    #[error("recovery threshold not met: need {0}, got {1}")]
    ThresholdNotMet(usize, usize),

    #[error("notary not in designated set: {0}")]
    NotaryNotInSet(String),

    #[error("duplicate notary signature: {0}")]
    DuplicateNotarySignature(String),

    #[error("invalid recovery mandate: {0}")]
    InvalidRecoveryMandate(String),

    #[error("no_retention disclosure requires TEE attestation: {0}")]
    NoRetentionRequiresTee(String),

    #[error("attestation error: {0}")]
    AttestationError(String),

    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}
