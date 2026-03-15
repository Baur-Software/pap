use serde::{Deserialize, Serialize};

use crate::PrincipalKeypair;

/// W3C DID Document (DID Core 1.0) for a `did:key` identifier.
/// Contains the public key and verification method. No personal information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    #[serde(rename = "controller")]
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

impl DidDocument {
    /// Create a DID document from a principal keypair.
    pub fn from_keypair(keypair: &PrincipalKeypair) -> Self {
        let did = keypair.did();
        let key_id = format!("{did}#key-1");

        // publicKeyMultibase: z-base58btc encoded raw public key
        let multibase = format!(
            "z{}",
            bs58::encode(keypair.public_key_bytes()).into_string()
        );

        Self {
            context: "https://www.w3.org/ns/did/v1".into(),
            id: did.clone(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                key_type: "Ed25519VerificationKey2020".into(),
                controller: did,
                public_key_multibase: multibase,
            }],
            authentication: vec![key_id],
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("DID document serialization cannot fail")
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_document_structure() {
        let kp = PrincipalKeypair::generate();
        let doc = DidDocument::from_keypair(&kp);

        assert_eq!(doc.context, "https://www.w3.org/ns/did/v1");
        assert!(doc.id.starts_with("did:key:z"));
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].key_type,
            "Ed25519VerificationKey2020"
        );
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.authentication[0], doc.verification_method[0].id);
    }

    #[test]
    fn did_document_json_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let doc = DidDocument::from_keypair(&kp);
        let json = doc.to_json();
        let doc2 = DidDocument::from_json(&json).unwrap();
        assert_eq!(doc.id, doc2.id);
        assert_eq!(
            doc.verification_method[0].public_key_multibase,
            doc2.verification_method[0].public_key_multibase
        );
    }

    #[test]
    fn did_document_contains_no_personal_info() {
        let kp = PrincipalKeypair::generate();
        let json = DidDocument::from_keypair(&kp).to_json();
        assert!(!json.contains("\"name\""));
        assert!(!json.contains("\"email\""));
    }
}
