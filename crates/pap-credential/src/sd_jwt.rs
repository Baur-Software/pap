use ed25519_dalek::{Signer, Verifier, VerifyingKey, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::CredentialError;

/// Selective Disclosure JWT — allows disclosing only specific claims
/// from a signed payload. Used in the session handshake for the
/// disclosure exchange step.
///
/// Reference: draft-ietf-oauth-selective-disclosure-jwt-08
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveDisclosureJwt {
    /// The issuer DID
    pub issuer: String,
    /// All claims (key -> value), each independently disclosable
    claims: HashMap<String, serde_json::Value>,
    /// Salt for each claim (key -> random salt)
    salts: HashMap<String, String>,
    /// The signed hash of all claims+salts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// A disclosure for a single claim — the salt, key, and value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disclosure {
    pub salt: String,
    pub key: String,
    pub value: serde_json::Value,
}

impl Disclosure {
    /// SHA-256 hash of this disclosure (for inclusion in the SD-JWT).
    pub fn hash(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("disclosure serialization cannot fail");
        let digest = Sha256::digest(&bytes);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }
}

impl SelectiveDisclosureJwt {
    /// Create a new SD-JWT with the given claims.
    pub fn new(issuer: String, claims: HashMap<String, serde_json::Value>) -> Self {
        let salts: HashMap<String, String> = claims
            .keys()
            .map(|k| (k.clone(), uuid::Uuid::new_v4().to_string()))
            .collect();
        Self {
            issuer,
            claims,
            salts,
            signature: None,
        }
    }

    /// Sign the SD-JWT (signs over the hash commitments of all claims).
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.commitment_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature = Some(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        );
    }

    /// Verify the SD-JWT signature.
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), CredentialError> {
        let sig_b64 = self
            .signature
            .as_ref()
            .ok_or_else(|| CredentialError::InvalidCredential("unsigned SD-JWT".into()))?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| CredentialError::VerificationFailed(e.to_string()))?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| {
                    CredentialError::VerificationFailed("invalid signature length".into())
                })?,
        );
        let bytes = self.commitment_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| CredentialError::VerificationFailed("signature mismatch".into()))
    }

    /// Produce disclosures for only the specified claim keys.
    /// This is the selective disclosure step — the holder reveals only
    /// what the mandate permits.
    pub fn disclose(&self, keys: &[&str]) -> Result<Vec<Disclosure>, CredentialError> {
        keys.iter()
            .map(|key| {
                let value = self
                    .claims
                    .get(*key)
                    .ok_or_else(|| {
                        CredentialError::DisclosureError(format!("claim not found: {key}"))
                    })?
                    .clone();
                let salt = self
                    .salts
                    .get(*key)
                    .ok_or_else(|| {
                        CredentialError::DisclosureError(format!("salt not found: {key}"))
                    })?
                    .clone();
                Ok(Disclosure {
                    salt,
                    key: key.to_string(),
                    value,
                })
            })
            .collect()
    }

    /// Verify that a set of disclosures matches the signed commitments.
    pub fn verify_disclosures(
        &self,
        disclosures: &[Disclosure],
        verifying_key: &VerifyingKey,
    ) -> Result<(), CredentialError> {
        // First verify the overall signature
        self.verify_signature(verifying_key)?;

        // Then verify each disclosure hash is in the commitment set
        let commitment_hashes = self.disclosure_hashes();
        for d in disclosures {
            let hash = d.hash();
            if !commitment_hashes.contains(&hash) {
                return Err(CredentialError::DisclosureError(format!(
                    "disclosure for '{}' does not match commitment",
                    d.key
                )));
            }
        }
        Ok(())
    }

    /// All claim keys in this SD-JWT.
    pub fn claim_keys(&self) -> Vec<&str> {
        self.claims.keys().map(|k| k.as_str()).collect()
    }

    /// The commitment bytes (sorted disclosure hashes) that get signed.
    fn commitment_bytes(&self) -> Vec<u8> {
        let mut hashes = self.disclosure_hashes();
        hashes.sort();
        serde_json::to_vec(&serde_json::json!({
            "issuer": self.issuer,
            "disclosure_hashes": hashes,
        }))
        .expect("commitment serialization cannot fail")
    }

    /// Compute the hash of each (salt, key, value) triple.
    fn disclosure_hashes(&self) -> Vec<String> {
        self.claims
            .iter()
            .map(|(key, value)| {
                let salt = &self.salts[key];
                let d = Disclosure {
                    salt: salt.clone(),
                    key: key.clone(),
                    value: value.clone(),
                };
                d.hash()
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_sd_jwt() -> (SelectiveDisclosureJwt, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();
        let mut claims = HashMap::new();
        claims.insert("schema:name".into(), serde_json::json!("Alice"));
        claims.insert("schema:email".into(), serde_json::json!("alice@example.com"));
        claims.insert(
            "schema:nationality".into(),
            serde_json::json!("Wonderland"),
        );

        let mut sd_jwt = SelectiveDisclosureJwt::new(did, claims);
        sd_jwt.sign(&key);
        (sd_jwt, key)
    }

    #[test]
    fn selective_disclosure_name_only() {
        let (sd_jwt, key) = make_sd_jwt();

        // Disclose only name — email and nationality stay hidden
        let disclosures = sd_jwt.disclose(&["schema:name"]).unwrap();
        assert_eq!(disclosures.len(), 1);
        assert_eq!(disclosures[0].key, "schema:name");
        assert_eq!(disclosures[0].value, serde_json::json!("Alice"));

        // Verify the disclosure matches the commitment
        assert!(sd_jwt
            .verify_disclosures(&disclosures, &key.verifying_key())
            .is_ok());
    }

    #[test]
    fn zero_disclosure() {
        let (sd_jwt, key) = make_sd_jwt();
        let disclosures = sd_jwt.disclose(&[]).unwrap();
        assert!(disclosures.is_empty());
        assert!(sd_jwt
            .verify_disclosures(&disclosures, &key.verifying_key())
            .is_ok());
    }

    #[test]
    fn tampered_disclosure_rejected() {
        let (sd_jwt, key) = make_sd_jwt();
        let mut disclosures = sd_jwt.disclose(&["schema:name"]).unwrap();
        // Tamper with the value
        disclosures[0].value = serde_json::json!("Bob");

        assert!(sd_jwt
            .verify_disclosures(&disclosures, &key.verifying_key())
            .is_err());
    }

    #[test]
    fn nonexistent_claim_error() {
        let (sd_jwt, _) = make_sd_jwt();
        assert!(sd_jwt.disclose(&["schema:address"]).is_err());
    }

    #[test]
    fn wrong_key_verify_fails() {
        let (sd_jwt, _) = make_sd_jwt();
        let wrong_key = SigningKey::generate(&mut OsRng);
        assert!(sd_jwt.verify_signature(&wrong_key.verifying_key()).is_err());
    }
}
