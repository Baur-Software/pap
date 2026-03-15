use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::CredentialError;

/// W3C Verifiable Credential (VC Data Model 2.0) wrapping a mandate payload.
/// The VC envelope provides interoperability with existing credential ecosystems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    pub id: String,

    #[serde(rename = "type")]
    pub credential_type: Vec<String>,

    pub issuer: String,

    #[serde(rename = "issuanceDate")]
    pub issuance_date: DateTime<Utc>,

    #[serde(rename = "expirationDate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>,

    #[serde(rename = "credentialSubject")]
    pub credential_subject: serde_json::Value,

    /// Proof section containing the signature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: DateTime<Utc>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl VerifiableCredential {
    /// Create a new VC wrapping a mandate as JSON payload.
    pub fn from_mandate(
        issuer_did: &str,
        subject: serde_json::Value,
        expiration: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/credentials/v2".into(),
                "https://www.w3.org/ns/credentials/examples/v2".into(),
            ],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            credential_type: vec!["VerifiableCredential".into(), "PAPMandateCredential".into()],
            issuer: issuer_did.to_string(),
            issuance_date: Utc::now(),
            expiration_date: expiration,
            credential_subject: subject,
            proof: None,
        }
    }

    /// Sign the credential with the issuer's key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey, verification_method: &str) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.proof = Some(CredentialProof {
            proof_type: "Ed25519Signature2020".into(),
            created: Utc::now(),
            verification_method: verification_method.to_string(),
            proof_purpose: "assertionMethod".into(),
            proof_value: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        });
    }

    /// Verify the credential's proof signature.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), CredentialError> {
        let proof = self
            .proof
            .as_ref()
            .ok_or_else(|| CredentialError::InvalidCredential("no proof".into()))?;

        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&proof.proof_value)
            .map_err(|e| CredentialError::VerificationFailed(e.to_string()))?;

        let signature =
            Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
                CredentialError::VerificationFailed("invalid signature length".into())
            })?);

        let bytes = self.canonical_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| CredentialError::VerificationFailed("signature mismatch".into()))
    }

    /// Check if the credential is expired.
    pub fn is_expired(&self) -> bool {
        self.expiration_date
            .map(|exp| Utc::now() > exp)
            .unwrap_or(false)
    }

    /// SHA-256 hash of the credential (excluding proof).
    pub fn hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("VC serialization cannot fail")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "@context": self.context,
            "id": self.id,
            "type": self.credential_type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date.to_rfc3339(),
            "expirationDate": self.expiration_date.map(|d| d.to_rfc3339()),
            "credentialSubject": self.credential_subject,
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn vc_sign_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();
        let key_id = format!("{did}#key-1");

        let subject = serde_json::json!({
            "id": "did:key:zagent",
            "scope": ["schema:SearchAction"],
        });

        let mut vc = VerifiableCredential::from_mandate(
            &did,
            subject,
            Some(Utc::now() + Duration::hours(1)),
        );

        vc.sign(&key, &key_id);
        assert!(vc.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn vc_wrong_key_fails() {
        let key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let mut vc = VerifiableCredential::from_mandate(
            &did,
            serde_json::json!({"id": "did:key:zagent"}),
            None,
        );
        vc.sign(&key, &format!("{did}#key-1"));
        assert!(vc.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn vc_structure() {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let vc = VerifiableCredential::from_mandate(
            &did,
            serde_json::json!({"id": "did:key:zagent"}),
            None,
        );

        assert!(vc
            .context
            .contains(&"https://www.w3.org/ns/credentials/v2".into()));
        assert!(vc.credential_type.contains(&"VerifiableCredential".into()));
        assert!(vc.credential_type.contains(&"PAPMandateCredential".into()));
        assert_eq!(vc.issuer, did);
        assert!(!vc.is_expired());
    }

    #[test]
    fn vc_json_roundtrip() {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let mut vc = VerifiableCredential::from_mandate(
            &did,
            serde_json::json!({"id": "did:key:zagent"}),
            Some(Utc::now() + Duration::hours(1)),
        );
        vc.sign(&key, &format!("{did}#key-1"));

        let json = vc.to_json();
        let vc2: VerifiableCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(vc.id, vc2.id);
        assert!(vc2.proof.is_some());
    }
}
