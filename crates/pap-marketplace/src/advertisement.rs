use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MarketplaceError;

/// A signed JSON-LD agent advertisement using Schema.org types.
/// Published by an agent operator, describing capabilities, disclosure
/// requirements, and return types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAdvertisement {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: String,

    /// Schema.org type for the service
    #[serde(rename = "@type")]
    pub schema_type: String,

    /// Human-readable name
    pub name: String,

    /// Provider organization with DID
    pub provider: Provider,

    /// Schema.org action types this agent can perform
    pub capability: Vec<String>,

    /// Schema.org object types this agent operates on
    pub object_types: Vec<String>,

    /// Properties this agent requires disclosed (Schema.org property refs)
    pub requires_disclosure: Vec<String>,

    /// Schema.org types this agent returns
    pub returns: Vec<String>,

    /// Minimum TTL in seconds for sessions with this agent
    #[serde(default)]
    pub ttl_min: u64,

    /// DID that signed this advertisement
    pub signed_by: String,

    /// Ed25519 signature (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    #[serde(rename = "@type")]
    pub schema_type: String,
    pub name: String,
    pub did: String,
}

impl AgentAdvertisement {
    /// Create a new agent advertisement.
    pub fn new(
        name: impl Into<String>,
        provider_name: impl Into<String>,
        operator_did: impl Into<String>,
        capability: Vec<String>,
        object_types: Vec<String>,
        requires_disclosure: Vec<String>,
        returns: Vec<String>,
    ) -> Self {
        let did = operator_did.into();
        Self {
            context: "https://schema.org".into(),
            schema_type: "schema:Service".into(),
            name: name.into(),
            provider: Provider {
                schema_type: "schema:Organization".into(),
                name: provider_name.into(),
                did: did.clone(),
            },
            capability,
            object_types,
            requires_disclosure,
            returns,
            ttl_min: 300,
            signed_by: did,
            signature: None,
        }
    }

    /// Sign the advertisement with the operator's key.
    pub fn sign(&mut self, signing_key: &ed25519_dalek::SigningKey) {
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    }

    /// Verify the advertisement's signature.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), MarketplaceError> {
        let sig_b64 = self.signature.as_ref().ok_or_else(|| {
            MarketplaceError::InvalidAdvertisement("unsigned advertisement".into())
        })?;
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e: base64::DecodeError| {
                MarketplaceError::VerificationFailed(e.to_string())
            })?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| MarketplaceError::VerificationFailed("invalid signature length".into()))?;
        let signature = Signature::from_bytes(&sig_array);
        let bytes = self.canonical_bytes();
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| MarketplaceError::VerificationFailed("signature mismatch".into()))
    }

    /// Check if this agent can perform a given Schema.org action.
    pub fn supports_action(&self, action: &str) -> bool {
        self.capability.iter().any(|c| c == action)
    }

    /// Check if the disclosure requirements can be satisfied by the given
    /// available properties (from the principal's disclosure profile).
    pub fn disclosure_satisfiable(&self, available: &[String]) -> bool {
        self.requires_disclosure
            .iter()
            .all(|req| available.contains(req))
    }

    /// SHA-256 hash of the advertisement.
    pub fn hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("advertisement serialization cannot fail")
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "@context": self.context,
            "@type": self.schema_type,
            "name": self.name,
            "provider": self.provider,
            "capability": self.capability,
            "object_types": self.object_types,
            "requires_disclosure": self.requires_disclosure,
            "returns": self.returns,
            "ttl_min": self.ttl_min,
            "signed_by": self.signed_by,
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_search_ad() -> (AgentAdvertisement, SigningKey) {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let mut ad = AgentAdvertisement::new(
            "Web Search Agent",
            "SearchCorp",
            &did,
            vec!["schema:SearchAction".into()],
            vec!["schema:WebPage".into()],
            vec![], // search requires no personal disclosure
            vec!["schema:SearchResult".into()],
        );
        ad.sign(&key);
        (ad, key)
    }

    #[test]
    fn advertisement_sign_verify() {
        let (ad, key) = make_search_ad();
        assert!(ad.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn advertisement_supports_action() {
        let (ad, _) = make_search_ad();
        assert!(ad.supports_action("schema:SearchAction"));
        assert!(!ad.supports_action("schema:PayAction"));
    }

    #[test]
    fn zero_disclosure_requirements() {
        let (ad, _) = make_search_ad();
        // Should be satisfiable with no available properties
        assert!(ad.disclosure_satisfiable(&[]));
    }

    #[test]
    fn disclosure_requirements_checked() {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let ad = AgentAdvertisement::new(
            "Flight Booking Agent",
            "FlightCorp",
            &did,
            vec!["schema:ReserveAction".into()],
            vec!["schema:Flight".into()],
            vec![
                "schema:Person.name".into(),
                "schema:Person.nationality".into(),
            ],
            vec!["schema:Flight".into(), "schema:Ticket".into()],
        );

        // Missing nationality
        assert!(!ad.disclosure_satisfiable(&["schema:Person.name".into()]));
        // Both present
        assert!(ad.disclosure_satisfiable(&[
            "schema:Person.name".into(),
            "schema:Person.nationality".into(),
        ]));
    }

    #[test]
    fn advertisement_json_roundtrip() {
        let (ad, _) = make_search_ad();
        let json = ad.to_json();
        let ad2: AgentAdvertisement = serde_json::from_str(&json).unwrap();
        assert_eq!(ad.name, ad2.name);
        assert_eq!(ad.capability, ad2.capability);
    }

    #[test]
    fn wrong_key_fails() {
        let (ad, _) = make_search_ad();
        let wrong_key = SigningKey::generate(&mut OsRng);
        assert!(ad.verify(&wrong_key.verifying_key()).is_err());
    }
}
