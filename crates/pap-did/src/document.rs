use serde::{Deserialize, Serialize};

use crate::algorithm::SignatureAlgorithm;
use crate::PrincipalKeypair;

/// A DID Document service endpoint.
///
/// PAP uses the `PAPObliviousHTTP` service type to publish the node's HPKE public key
/// so that clients can encrypt OHTTP requests without out-of-band key distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
    /// Base64url-encoded RFC 9458 §5 key config — present only for `PAPObliviousHTTP` services.
    #[serde(rename = "ohthpKeyConfig", skip_serializing_if = "Option::is_none")]
    pub ohttp_key_config: Option<String>,
}

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
    /// Optional service endpoints (e.g. `PAPObliviousHTTP` for OHTTP key distribution).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
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
    /// The signature algorithm for this verification method.
    /// Defaults to Ed25519 for backward compatibility with PAP v1.0 documents.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
}

impl DidDocument {
    /// Create a DID document from a principal keypair.
    pub fn from_keypair(keypair: &PrincipalKeypair) -> Self {
        let did = keypair.did();
        let key_id = format!("{did}#key-1");

        // publicKeyMultibase: z-base58btc(0xed01 ++ public_key_bytes)
        // Multicodec prefix 0xed01 identifies Ed25519 public key
        let mut prefixed = Vec::with_capacity(34);
        prefixed.push(0xed);
        prefixed.push(0x01);
        prefixed.extend_from_slice(&keypair.public_key_bytes());
        let multibase = format!("z{}", bs58::encode(&prefixed).into_string());

        Self {
            context: "https://www.w3.org/ns/did/v1".into(),
            id: did.clone(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                key_type: SignatureAlgorithm::Ed25519.verification_key_type().into(),
                controller: did,
                public_key_multibase: multibase,
                algorithm: SignatureAlgorithm::Ed25519,
            }],
            authentication: vec![key_id],
            service: None,
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

    #[test]
    fn verification_method_algorithm_field() {
        let kp = PrincipalKeypair::generate();
        let doc = DidDocument::from_keypair(&kp);
        assert_eq!(
            doc.verification_method[0].algorithm,
            SignatureAlgorithm::Ed25519
        );
    }

    #[test]
    fn did_document_without_algorithm_field_deserializes() {
        // Simulate a v1.0 document that lacks the algorithm field
        let json = r#"{
            "@context": "https://www.w3.org/ns/did/v1",
            "id": "did:key:ztest",
            "verificationMethod": [{
                "id": "did:key:ztest#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:key:ztest",
                "publicKeyMultibase": "z1234"
            }],
            "authentication": ["did:key:ztest#key-1"]
        }"#;
        let doc = DidDocument::from_json(json).unwrap();
        assert_eq!(
            doc.verification_method[0].algorithm,
            SignatureAlgorithm::Ed25519
        );
    }

    #[test]
    fn public_key_multibase_includes_multicodec_prefix() {
        let kp = PrincipalKeypair::generate();
        let doc = DidDocument::from_keypair(&kp);
        let multibase = &doc.verification_method[0].public_key_multibase;

        // Strip the 'z' multibase prefix and decode base58
        let decoded = bs58::decode(&multibase[1..]).into_vec().unwrap();

        // Must be 34 bytes: 2-byte multicodec prefix + 32-byte public key
        assert_eq!(decoded.len(), 34, "expected 34 bytes (2 prefix + 32 key)");
        assert_eq!(decoded[0], 0xed, "multicodec prefix byte 0");
        assert_eq!(decoded[1], 0x01, "multicodec prefix byte 1");
        assert_eq!(&decoded[2..], &kp.public_key_bytes(), "public key bytes");
    }

    #[test]
    fn from_json_rejects_empty_string() {
        assert!(DidDocument::from_json("").is_err());
    }

    #[test]
    fn from_json_rejects_invalid_json() {
        assert!(DidDocument::from_json("not json {{{").is_err());
    }
}
