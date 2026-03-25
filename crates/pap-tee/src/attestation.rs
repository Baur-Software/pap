//! TEE attestation evidence types (spec section 13.6).
//!
//! A mandate or session MAY carry a TEE attestation to provide evidence
//! that an agent is executing within an isolated enclave. TEE attestation
//! is OPTIONAL and does NOT elevate a TEE to equivalence with local trust.
//!
//! The `AttestationEvidence` struct follows the RATS architecture (RFC 9334)
//! evidence format: platform-specific attestation reports bound to a session
//! via a challenge nonce.

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::error::TeeError;

/// TEE platform identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnclaveType {
    /// Intel SGX
    Sgx,
    /// AMD SEV-SNP
    SevSnp,
    /// ARM TrustZone
    Trustzone,
    /// Software-simulated enclave (testing only)
    Software,
}

impl EnclaveType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sgx => "sgx",
            Self::SevSnp => "sev-snp",
            Self::Trustzone => "trustzone",
            Self::Software => "software",
        }
    }
}

impl std::fmt::Display for EnclaveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// TEE attestation evidence per spec section 13.6.1.
///
/// All binary fields use base64url-no-pad encoding. The `nonce` field
/// binds this attestation to a specific session challenge, preventing
/// replay across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// TEE platform identifier
    pub enclave_type: EnclaveType,
    /// Enclave measurement hash (base64url-no-pad, SHA-256)
    pub measurement: String,
    /// Platform-specific attestation report (base64url-no-pad)
    pub attestation_report: String,
    /// Attestation generation timestamp (RFC 3339)
    pub timestamp: DateTime<Utc>,
    /// Challenge nonce binding this attestation to the current session (UUID v4)
    pub nonce: String,
}

impl AttestationEvidence {
    /// Validate structural integrity of the attestation evidence.
    ///
    /// Checks that measurement and report are valid base64url and that
    /// the measurement is exactly 32 bytes (SHA-256).
    pub fn validate(&self) -> Result<(), TeeError> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let measurement_bytes = engine.decode(&self.measurement).map_err(|e| {
            TeeError::InvalidMeasurement(format!("invalid base64url encoding: {e}"))
        })?;
        if measurement_bytes.len() != 32 {
            return Err(TeeError::InvalidMeasurement(format!(
                "measurement must be 32 bytes (SHA-256), got {}",
                measurement_bytes.len()
            )));
        }

        engine
            .decode(&self.attestation_report)
            .map_err(|e| TeeError::InvalidReport(format!("invalid base64url encoding: {e}")))?;

        Ok(())
    }

    /// Convert to a `serde_json::Value` for protocol-level transport.
    pub fn into_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("AttestationEvidence serialization cannot fail")
    }

    /// Parse from a `serde_json::Value` received in a protocol message.
    pub fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// Compute the SHA-256 measurement hash for a given enclave binary.
    pub fn compute_measurement(enclave_binary: &[u8]) -> String {
        let digest = sha2::Sha256::digest(enclave_binary);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence() -> AttestationEvidence {
        let measurement = AttestationEvidence::compute_measurement(b"test-enclave-binary-v1.0.0");
        let report = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(b"mock-attestation-report-data-for-testing");

        AttestationEvidence {
            enclave_type: EnclaveType::Software,
            measurement,
            attestation_report: report,
            timestamp: Utc::now(),
            nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    #[test]
    fn attestation_validate_valid() {
        let evidence = sample_evidence();
        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn attestation_validate_invalid_measurement_encoding() {
        let mut evidence = sample_evidence();
        evidence.measurement = "not-valid-base64!!!".into();
        assert!(matches!(
            evidence.validate(),
            Err(TeeError::InvalidMeasurement(_))
        ));
    }

    #[test]
    fn attestation_validate_wrong_measurement_length() {
        let mut evidence = sample_evidence();
        evidence.measurement =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"too-short");
        assert!(matches!(
            evidence.validate(),
            Err(TeeError::InvalidMeasurement(_))
        ));
    }

    #[test]
    fn attestation_validate_invalid_report_encoding() {
        let mut evidence = sample_evidence();
        evidence.attestation_report = "not-valid!!!".into();
        assert!(matches!(
            evidence.validate(),
            Err(TeeError::InvalidReport(_))
        ));
    }

    #[test]
    fn attestation_serialization_roundtrip() {
        let evidence = sample_evidence();
        let json = serde_json::to_string(&evidence).unwrap();
        let restored: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence.enclave_type, restored.enclave_type);
        assert_eq!(evidence.measurement, restored.measurement);
        assert_eq!(evidence.nonce, restored.nonce);
    }

    #[test]
    fn attestation_value_roundtrip() {
        let evidence = sample_evidence();
        let value = evidence.into_value();
        let restored = AttestationEvidence::from_value(value).unwrap();
        assert_eq!(restored.enclave_type, EnclaveType::Software);
    }

    #[test]
    fn enclave_type_serde_kebab_case() {
        let sgx = serde_json::to_string(&EnclaveType::Sgx).unwrap();
        assert_eq!(sgx, "\"sgx\"");

        let sev = serde_json::to_string(&EnclaveType::SevSnp).unwrap();
        assert_eq!(sev, "\"sev-snp\"");

        let tz = serde_json::to_string(&EnclaveType::Trustzone).unwrap();
        assert_eq!(tz, "\"trustzone\"");

        let sw = serde_json::to_string(&EnclaveType::Software).unwrap();
        assert_eq!(sw, "\"software\"");
    }

    #[test]
    fn compute_measurement_deterministic() {
        let m1 = AttestationEvidence::compute_measurement(b"enclave-v1");
        let m2 = AttestationEvidence::compute_measurement(b"enclave-v1");
        assert_eq!(m1, m2);

        let m3 = AttestationEvidence::compute_measurement(b"enclave-v2");
        assert_ne!(m1, m3);
    }

    #[test]
    fn attestation_timestamp_preserved() {
        let now = Utc::now();
        let mut evidence = sample_evidence();
        evidence.timestamp = now;

        let json = serde_json::to_string(&evidence).unwrap();
        let restored: AttestationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(
            evidence.timestamp.timestamp(),
            restored.timestamp.timestamp()
        );
    }

    #[test]
    fn enclave_type_display() {
        assert_eq!(EnclaveType::Sgx.to_string(), "sgx");
        assert_eq!(EnclaveType::SevSnp.to_string(), "sev-snp");
        assert_eq!(EnclaveType::Trustzone.to_string(), "trustzone");
        assert_eq!(EnclaveType::Software.to_string(), "software");
    }
}
