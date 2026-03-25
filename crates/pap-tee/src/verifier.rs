//! Attestation verification logic (spec section 13.6.2).
//!
//! A verifier MUST:
//! 1. Verify the attestation_report against the TEE platform's root of trust
//! 2. Verify that measurement matches an expected enclave binary hash
//! 3. Verify that nonce matches the session's challenge nonce
//! 4. Verify that timestamp is within an acceptable window (60 seconds)

use chrono::Utc;

use crate::attestation::AttestationEvidence;
use crate::error::TeeError;

/// Maximum age of an attestation before it is considered stale (spec: 60 seconds).
pub const MAX_ATTESTATION_AGE_SECS: u64 = 60;

/// Trait for platform-specific attestation verification.
///
/// Implementations verify the `attestation_report` against their platform's
/// root of trust. The common checks (nonce, timestamp, measurement format)
/// are provided by [`verify_common`].
pub trait AttestationVerifier {
    /// Verify an attestation evidence object.
    ///
    /// Implementations MUST call [`verify_common`] first, then perform
    /// platform-specific report verification.
    fn verify(
        &self,
        evidence: &AttestationEvidence,
        expected_nonce: &str,
        allowed_measurements: &[String],
    ) -> Result<(), TeeError>;
}

/// Common verification checks shared by all verifier implementations.
///
/// Checks:
/// - Structural validity (base64url encoding, measurement length)
/// - Nonce matches expected session challenge
/// - Timestamp within acceptable window
/// - Measurement in allowed set
pub fn verify_common(
    evidence: &AttestationEvidence,
    expected_nonce: &str,
    allowed_measurements: &[String],
    max_age_secs: u64,
) -> Result<(), TeeError> {
    // Structural validation
    evidence.validate()?;

    // Nonce binding
    if evidence.nonce != expected_nonce {
        return Err(TeeError::NonceMismatch {
            expected: expected_nonce.to_string(),
            got: evidence.nonce.clone(),
        });
    }

    // Timestamp freshness
    let age = Utc::now()
        .signed_duration_since(evidence.timestamp)
        .num_seconds();
    if age < 0 || age as u64 > max_age_secs {
        return Err(TeeError::AttestationExpired { max_age_secs });
    }

    // Measurement allowlist
    if !allowed_measurements.contains(&evidence.measurement) {
        return Err(TeeError::UntrustedMeasurement(evidence.measurement.clone()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestationEvidence, EnclaveType};

    fn make_evidence(nonce: &str, measurement: &str) -> AttestationEvidence {
        use base64::Engine;
        AttestationEvidence {
            enclave_type: EnclaveType::Software,
            measurement: measurement.to_string(),
            attestation_report: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(b"mock-report"),
            timestamp: Utc::now(),
            nonce: nonce.to_string(),
        }
    }

    #[test]
    fn verify_common_valid() {
        let measurement = AttestationEvidence::compute_measurement(b"test-enclave");
        let nonce = uuid::Uuid::new_v4().to_string();
        let evidence = make_evidence(&nonce, &measurement);
        assert!(verify_common(&evidence, &nonce, &[measurement], MAX_ATTESTATION_AGE_SECS).is_ok());
    }

    #[test]
    fn verify_common_nonce_mismatch() {
        let measurement = AttestationEvidence::compute_measurement(b"test-enclave");
        let evidence = make_evidence("nonce-a", &measurement);
        let result = verify_common(
            &evidence,
            "nonce-b",
            &[measurement],
            MAX_ATTESTATION_AGE_SECS,
        );
        assert!(matches!(result, Err(TeeError::NonceMismatch { .. })));
    }

    #[test]
    fn verify_common_expired_attestation() {
        let measurement = AttestationEvidence::compute_measurement(b"test-enclave");
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut evidence = make_evidence(&nonce, &measurement);
        evidence.timestamp = Utc::now() - chrono::Duration::seconds(120);
        let result = verify_common(&evidence, &nonce, &[measurement], MAX_ATTESTATION_AGE_SECS);
        assert!(matches!(result, Err(TeeError::AttestationExpired { .. })));
    }

    #[test]
    fn verify_common_untrusted_measurement() {
        let measurement = AttestationEvidence::compute_measurement(b"test-enclave");
        let trusted = AttestationEvidence::compute_measurement(b"trusted-enclave");
        let nonce = uuid::Uuid::new_v4().to_string();
        let evidence = make_evidence(&nonce, &measurement);
        let result = verify_common(&evidence, &nonce, &[trusted], MAX_ATTESTATION_AGE_SECS);
        assert!(matches!(result, Err(TeeError::UntrustedMeasurement(_))));
    }

    #[test]
    fn verify_common_future_timestamp_rejected() {
        let measurement = AttestationEvidence::compute_measurement(b"test-enclave");
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut evidence = make_evidence(&nonce, &measurement);
        evidence.timestamp = Utc::now() + chrono::Duration::seconds(120);
        let result = verify_common(&evidence, &nonce, &[measurement], MAX_ATTESTATION_AGE_SECS);
        assert!(matches!(result, Err(TeeError::AttestationExpired { .. })));
    }
}
