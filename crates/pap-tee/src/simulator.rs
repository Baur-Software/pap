//! Software-simulated TEE attestation for integration testing.
//!
//! The `SoftwareSimulator` generates attestation evidence with
//! `EnclaveType::Software` and signs the report with an Ed25519 key.
//! This allows end-to-end testing of the attestation flow without
//! requiring actual TEE hardware.
//!
//! MUST NOT be used in production. The `software` enclave type makes
//! it explicit that the attestation is simulated.

use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use crate::attestation::{AttestationEvidence, EnclaveType};
use crate::error::TeeError;
use crate::verifier::{verify_common, AttestationVerifier, MAX_ATTESTATION_AGE_SECS};

/// Software-simulated TEE attestation provider.
///
/// Generates attestation evidence with a deterministic measurement
/// derived from a simulated enclave binary, and signs the report
/// with an Ed25519 key pair.
pub struct SoftwareSimulator {
    /// SHA-256 of the simulated enclave binary (base64url-no-pad)
    measurement: String,
    /// Signing key simulating the enclave's attestation key
    signing_key: ed25519_dalek::SigningKey,
}

impl SoftwareSimulator {
    /// Create a new software simulator with the given enclave binary.
    ///
    /// The measurement is computed as SHA-256 of the binary content.
    pub fn new(enclave_binary: &[u8]) -> Self {
        let measurement = AttestationEvidence::compute_measurement(enclave_binary);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            measurement,
            signing_key,
        }
    }

    /// The verifying key for report signature verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The enclave measurement this simulator produces.
    pub fn measurement(&self) -> &str {
        &self.measurement
    }

    /// Generate attestation evidence bound to the given session nonce.
    ///
    /// The attestation report is a signed payload containing the
    /// measurement and nonce, simulating a platform-specific report.
    pub fn generate_attestation(&self, nonce: &str) -> AttestationEvidence {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Build report payload: measurement || nonce
        let mut report_payload = Vec::new();
        report_payload.extend_from_slice(self.measurement.as_bytes());
        report_payload.extend_from_slice(b"|");
        report_payload.extend_from_slice(nonce.as_bytes());

        // Sign the payload
        let signature = self.signing_key.sign(&report_payload);

        // Report = payload || signature
        let mut report_bytes = report_payload.clone();
        report_bytes.extend_from_slice(&signature.to_bytes());

        AttestationEvidence {
            enclave_type: EnclaveType::Software,
            measurement: self.measurement.clone(),
            attestation_report: engine.encode(&report_bytes),
            timestamp: Utc::now(),
            nonce: nonce.to_string(),
        }
    }

    /// Verify a simulated attestation report's signature.
    fn verify_report(&self, evidence: &AttestationEvidence) -> Result<(), TeeError> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let report_bytes = engine
            .decode(&evidence.attestation_report)
            .map_err(|e| TeeError::InvalidReport(format!("invalid base64url: {e}")))?;

        if report_bytes.len() < 64 {
            return Err(TeeError::VerificationFailed(
                "report too short for signature".into(),
            ));
        }

        let (payload, sig_bytes) = report_bytes.split_at(report_bytes.len() - 64);
        let signature = Signature::from_bytes(
            sig_bytes
                .try_into()
                .map_err(|_| TeeError::VerificationFailed("invalid signature length".into()))?,
        );

        self.verifying_key()
            .verify(payload, &signature)
            .map_err(|_| TeeError::VerificationFailed("report signature invalid".into()))
    }
}

impl AttestationVerifier for SoftwareSimulator {
    fn verify(
        &self,
        evidence: &AttestationEvidence,
        expected_nonce: &str,
        allowed_measurements: &[String],
    ) -> Result<(), TeeError> {
        // Common checks: structure, nonce, timestamp, measurement allowlist
        verify_common(
            evidence,
            expected_nonce,
            allowed_measurements,
            MAX_ATTESTATION_AGE_SECS,
        )?;

        // Platform-specific: verify the simulated report signature
        self.verify_report(evidence)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BINARY: &[u8] = b"pap-agent-enclave-v1.0.0-test";

    #[test]
    fn simulator_generate_and_verify() {
        let sim = SoftwareSimulator::new(TEST_BINARY);
        let nonce = uuid::Uuid::new_v4().to_string();
        let evidence = sim.generate_attestation(&nonce);

        assert_eq!(evidence.enclave_type, EnclaveType::Software);
        assert_eq!(evidence.measurement, sim.measurement());
        assert_eq!(evidence.nonce, nonce);

        let allowed = vec![sim.measurement().to_string()];
        assert!(sim.verify(&evidence, &nonce, &allowed).is_ok());
    }

    #[test]
    fn simulator_wrong_nonce_rejected() {
        let sim = SoftwareSimulator::new(TEST_BINARY);
        let evidence = sim.generate_attestation("nonce-a");

        let allowed = vec![sim.measurement().to_string()];
        let result = sim.verify(&evidence, "nonce-b", &allowed);
        assert!(matches!(result, Err(TeeError::NonceMismatch { .. })));
    }

    #[test]
    fn simulator_tampered_report_rejected() {
        let sim = SoftwareSimulator::new(TEST_BINARY);
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut evidence = sim.generate_attestation(&nonce);

        // Tamper with the report
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut bytes = engine.decode(&evidence.attestation_report).unwrap();
        if let Some(byte) = bytes.first_mut() {
            *byte ^= 0xFF;
        }
        evidence.attestation_report = engine.encode(&bytes);

        let allowed = vec![sim.measurement().to_string()];
        let result = sim.verify(&evidence, &nonce, &allowed);
        assert!(matches!(result, Err(TeeError::VerificationFailed(_))));
    }

    #[test]
    fn simulator_untrusted_measurement_rejected() {
        let sim = SoftwareSimulator::new(TEST_BINARY);
        let nonce = uuid::Uuid::new_v4().to_string();
        let evidence = sim.generate_attestation(&nonce);

        let other_measurement = AttestationEvidence::compute_measurement(b"different-enclave");
        let result = sim.verify(&evidence, &nonce, &[other_measurement]);
        assert!(matches!(result, Err(TeeError::UntrustedMeasurement(_))));
    }

    #[test]
    fn simulator_expired_rejected() {
        let sim = SoftwareSimulator::new(TEST_BINARY);
        let nonce = uuid::Uuid::new_v4().to_string();
        let mut evidence = sim.generate_attestation(&nonce);
        evidence.timestamp = Utc::now() - chrono::Duration::seconds(120);

        let allowed = vec![sim.measurement().to_string()];
        let result = sim.verify(&evidence, &nonce, &allowed);
        assert!(matches!(result, Err(TeeError::AttestationExpired { .. })));
    }

    #[test]
    fn simulator_measurement_deterministic() {
        let sim1 = SoftwareSimulator::new(TEST_BINARY);
        let sim2 = SoftwareSimulator::new(TEST_BINARY);
        assert_eq!(sim1.measurement(), sim2.measurement());
    }

    #[test]
    fn simulator_different_binaries_different_measurements() {
        let sim1 = SoftwareSimulator::new(b"enclave-v1");
        let sim2 = SoftwareSimulator::new(b"enclave-v2");
        assert_ne!(sim1.measurement(), sim2.measurement());
    }

    #[test]
    fn simulator_structural_validation() {
        let sim = SoftwareSimulator::new(TEST_BINARY);
        let nonce = uuid::Uuid::new_v4().to_string();
        let evidence = sim.generate_attestation(&nonce);
        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn cross_simulator_verification_fails() {
        let sim_a = SoftwareSimulator::new(TEST_BINARY);
        let sim_b = SoftwareSimulator::new(TEST_BINARY);

        let nonce = uuid::Uuid::new_v4().to_string();
        let evidence = sim_a.generate_attestation(&nonce);

        // sim_b has the same measurement but different signing key
        let allowed = vec![sim_b.measurement().to_string()];
        let result = sim_b.verify(&evidence, &nonce, &allowed);
        assert!(matches!(result, Err(TeeError::VerificationFailed(_))));
    }
}
