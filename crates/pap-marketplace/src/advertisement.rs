use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use pap_did::SignatureAlgorithm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::MarketplaceError;

fn default_version() -> String {
    "0.1.0".into()
}

/// Raw, verifiable operator metrics attached as advertisement metadata.
///
/// These metrics are derived from co-signed transaction receipts and TEE
/// attestations. The marketplace exposes them as-is without interpretation,
/// ranking, or tier assignment. Principals evaluate metrics locally using
/// their own trust policies.
///
/// # Anti-Platform-Capture Guarantee
///
/// Metrics are **never** used by the registry for sorting, ranking, or
/// filtering. Any ordering imposed on query results would recreate the
/// platform capture dynamics that PAP is designed to eliminate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OperatorMetrics {
    /// Total co-signed receipts the operator has participated in.
    pub total_receipts: u64,

    /// Receipts where both parties provided attestations.
    pub bilateral_attestations: u64,

    /// Number of distinct session DID counterparties.
    pub unique_counterparties: u64,

    /// Distinct Schema.org action types the operator has performed.
    pub action_types: Vec<String>,

    /// Percentage of sessions with TEE attestation (0.0 to 1.0).
    pub tee_sessions_pct: f64,

    /// RFC 3339 timestamp of the operator's first advertisement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,

    /// Number of days the operator has been active in the federation.
    pub uptime_days: u64,
}

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

    /// Semantic version of this agent (e.g. "1.0.0").
    ///
    /// Included in signature computation — the version is an identity claim.
    /// When configurable_properties change (add, remove, rename, constraint
    /// changes), the version should bump. Setting overrides are pinned to
    /// the version they were configured against.
    #[serde(default = "default_version")]
    pub version: String,

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

    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,

    /// Signature (base64-encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Raw operator metrics for principal-side evaluation.
    ///
    /// This field is **excluded** from signature computation because metrics
    /// change over time while the signature covers static identity fields.
    /// The marketplace never uses this field for ranking or filtering.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics: Option<OperatorMetrics>,

    /// Configurable properties this agent exposes to principals.
    ///
    /// Each entry is a schema.org `PropertyValueSpecification` describing
    /// a tunable parameter — name, type constraints, default value. Stored
    /// as raw `serde_json::Value` because these ARE vocabulary objects that
    /// the renderer projects directly; typing them as Rust structs would
    /// recreate the coupling the renderer is designed to eliminate.
    ///
    /// Like `metrics`, this field is **excluded** from signature computation
    /// because configurable properties are mutable metadata that change over
    /// time. The signature covers identity and capability fields only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configurable_properties: Vec<serde_json::Value>,
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
            version: default_version(),
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
            algorithm: SignatureAlgorithm::default(),
            signature: None,
            metrics: None,
            configurable_properties: Vec::new(),
        }
    }

    /// Attach operator metrics to this advertisement.
    ///
    /// Metrics are metadata only and are excluded from signature computation,
    /// so they can be attached or updated without re-signing.
    pub fn with_metrics(mut self, metrics: OperatorMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach configurable properties to this advertisement.
    ///
    /// Each entry should be a schema.org `PropertyValueSpecification` object.
    /// Like metrics, these are excluded from signature computation and can be
    /// attached or updated without re-signing.
    /// Set the agent version (semver). Included in signature computation.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    pub fn with_configurable_properties(mut self, props: Vec<serde_json::Value>) -> Self {
        self.configurable_properties = props;
        self
    }

    /// Sign the advertisement with the operator's key.
    pub fn sign(
        &mut self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<(), MarketplaceError> {
        if self.algorithm != SignatureAlgorithm::Ed25519 {
            return Err(MarketplaceError::UnsupportedAlgorithm(format!(
                "{:?}",
                self.algorithm
            )));
        }
        let bytes = self.canonical_bytes();
        let sig = signing_key.sign(&bytes);
        use base64::Engine;
        self.signature =
            Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        Ok(())
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

    /// Produce the canonical byte representation for signing/hashing.
    ///
    /// **Intentionally excludes** `signature` (obviously) and `metrics`.
    /// Metrics are mutable metadata that change over time; the signature
    /// covers only the static identity and capability fields.
    fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = serde_json::json!({
            "@context": self.context,
            "@type": self.schema_type,
            "name": self.name,
            "version": self.version,
            "provider": self.provider,
            "capability": self.capability,
            "object_types": self.object_types,
            "requires_disclosure": self.requires_disclosure,
            "returns": self.returns,
            "ttl_min": self.ttl_min,
            "signed_by": self.signed_by,
            // NOTE: `signature`, `metrics`, and `configurable_properties`
            // are deliberately omitted from the canonical form.
            // - `signature`: it's what we're computing.
            // - `metrics`: mutable metadata evaluated locally by principals.
            // - `configurable_properties`: mutable setting descriptors.
            // The `version` field IS included — when properties change,
            // the version bumps and the signature must be recomputed.
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
        ad.sign(&key).unwrap();
        (ad, key)
    }

    /// Parameterized advertisement sign/verify test body.
    fn advertisement_sign_verify_for_algorithm(algorithm: SignatureAlgorithm) {
        assert_eq!(algorithm, SignatureAlgorithm::Ed25519);
        let (ad, key) = make_search_ad();
        assert_eq!(ad.algorithm, algorithm);
        assert!(ad.verify(&key.verifying_key()).is_ok());
    }

    #[test]
    fn advertisement_sign_verify() {
        advertisement_sign_verify_for_algorithm(SignatureAlgorithm::Ed25519);
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

    fn sample_metrics() -> OperatorMetrics {
        OperatorMetrics {
            total_receipts: 150,
            bilateral_attestations: 120,
            unique_counterparties: 42,
            action_types: vec!["schema:SearchAction".into(), "schema:TradeAction".into()],
            tee_sessions_pct: 0.85,
            first_seen: Some("2025-01-15T08:30:00Z".into()),
            uptime_days: 90,
        }
    }

    #[test]
    fn metrics_excluded_from_canonical_bytes() {
        // Sign an advertisement without metrics, then attach metrics.
        // The signature must still verify because metrics are excluded
        // from canonical_bytes().
        let (ad, key) = make_search_ad();
        let hash_before = ad.hash();

        let ad_with_metrics = ad.clone().with_metrics(sample_metrics());

        // Signature still verifies after attaching metrics
        assert!(ad_with_metrics.verify(&key.verifying_key()).is_ok());
        // Hash is computed from canonical_bytes, so it should be identical
        assert_eq!(hash_before, ad_with_metrics.hash());
    }

    #[test]
    fn metrics_excluded_different_metrics_same_signature() {
        // Two copies of the same ad with different metrics must produce
        // the same canonical bytes and hash.
        let (ad, key) = make_search_ad();

        let metrics_a = OperatorMetrics {
            total_receipts: 10,
            bilateral_attestations: 5,
            unique_counterparties: 3,
            action_types: vec!["schema:SearchAction".into()],
            tee_sessions_pct: 0.5,
            first_seen: None,
            uptime_days: 7,
        };
        let metrics_b = OperatorMetrics {
            total_receipts: 99999,
            bilateral_attestations: 99999,
            unique_counterparties: 99999,
            action_types: vec!["schema:PayAction".into(), "schema:TradeAction".into()],
            tee_sessions_pct: 1.0,
            first_seen: Some("2024-01-01T00:00:00Z".into()),
            uptime_days: 365,
        };

        let ad_a = ad.clone().with_metrics(metrics_a);
        let ad_b = ad.clone().with_metrics(metrics_b);

        // Both should verify with the same key
        assert!(ad_a.verify(&key.verifying_key()).is_ok());
        assert!(ad_b.verify(&key.verifying_key()).is_ok());
        // Both should produce the same hash
        assert_eq!(ad_a.hash(), ad_b.hash());
    }

    #[test]
    fn with_metrics_builder() {
        let (ad, _) = make_search_ad();
        assert!(ad.metrics.is_none());

        let metrics = sample_metrics();
        let ad = ad.with_metrics(metrics.clone());
        assert_eq!(ad.metrics.as_ref(), Some(&metrics));
    }

    #[test]
    fn metrics_serialization_roundtrip() {
        let metrics = sample_metrics();
        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: OperatorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(metrics, deserialized);
    }

    #[test]
    fn advertisement_with_metrics_json_roundtrip() {
        let (ad, _) = make_search_ad();
        let ad = ad.with_metrics(sample_metrics());

        let json = ad.to_json();
        let ad2: AgentAdvertisement = serde_json::from_str(&json).unwrap();
        assert_eq!(ad.name, ad2.name);
        assert_eq!(ad.metrics, ad2.metrics);
    }

    #[test]
    fn advertisement_without_metrics_deserializes_none() {
        // An advertisement serialized without metrics should deserialize
        // with metrics: None (backward compatibility).
        let (ad, _) = make_search_ad();
        assert!(ad.metrics.is_none());

        let json = ad.to_json();
        let ad2: AgentAdvertisement = serde_json::from_str(&json).unwrap();
        assert!(ad2.metrics.is_none());
    }

    #[test]
    fn metrics_first_seen_optional() {
        let metrics = OperatorMetrics {
            total_receipts: 0,
            bilateral_attestations: 0,
            unique_counterparties: 0,
            action_types: vec![],
            tee_sessions_pct: 0.0,
            first_seen: None,
            uptime_days: 0,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        // first_seen should be absent from JSON when None
        assert!(!json.contains("first_seen"));
        let deserialized: OperatorMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.first_seen, None);
    }

    // ── Configurable properties ─────────────────────────────────────────────

    fn sample_configurable_properties() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "@type": "PropertyValueSpecification",
                "valueName": "safe_search",
                "name": "Safe Search",
                "description": "Filter explicit content from results",
                "defaultValue": true
            }),
            serde_json::json!({
                "@type": "PropertyValueSpecification",
                "valueName": "max_results",
                "name": "Maximum Results",
                "description": "Maximum results returned per query",
                "defaultValue": 10,
                "minValue": 1,
                "maxValue": 50
            }),
        ]
    }

    #[test]
    fn configurable_properties_excluded_from_signature() {
        // Sign an advertisement, then attach configurable_properties.
        // The signature must still verify because they're excluded
        // from canonical_bytes().
        let (ad, key) = make_search_ad();
        let hash_before = ad.hash();

        let ad_with_props = ad
            .clone()
            .with_configurable_properties(sample_configurable_properties());

        assert!(ad_with_props.verify(&key.verifying_key()).is_ok());
        assert_eq!(hash_before, ad_with_props.hash());
    }

    #[test]
    fn configurable_properties_different_props_same_signature() {
        let (ad, key) = make_search_ad();

        let ad_a = ad
            .clone()
            .with_configurable_properties(sample_configurable_properties());
        let ad_b = ad
            .clone()
            .with_configurable_properties(vec![serde_json::json!({
                "@type": "PropertyValueSpecification",
                "valueName": "totally_different",
                "defaultValue": "something"
            })]);

        assert!(ad_a.verify(&key.verifying_key()).is_ok());
        assert!(ad_b.verify(&key.verifying_key()).is_ok());
        assert_eq!(ad_a.hash(), ad_b.hash());
    }

    #[test]
    fn configurable_properties_json_roundtrip() {
        let (ad, _) = make_search_ad();
        let ad = ad.with_configurable_properties(sample_configurable_properties());

        let json = ad.to_json();
        let ad2: AgentAdvertisement = serde_json::from_str(&json).unwrap();
        assert_eq!(ad.configurable_properties.len(), 2);
        assert_eq!(ad2.configurable_properties.len(), 2);
        assert_eq!(ad2.configurable_properties[0]["valueName"], "safe_search");
    }

    #[test]
    fn configurable_properties_absent_deserializes_empty() {
        // Backward compatibility: advertisements without the field
        // should deserialize with an empty Vec.
        let (ad, _) = make_search_ad();
        assert!(ad.configurable_properties.is_empty());

        let json = ad.to_json();
        let ad2: AgentAdvertisement = serde_json::from_str(&json).unwrap();
        assert!(ad2.configurable_properties.is_empty());
    }

    #[test]
    fn with_configurable_properties_builder() {
        let (ad, _) = make_search_ad();
        assert!(ad.configurable_properties.is_empty());

        let props = sample_configurable_properties();
        let ad = ad.with_configurable_properties(props.clone());
        assert_eq!(ad.configurable_properties.len(), 2);
    }

    // ── Version tests ──────────────────────────────────────────────────

    #[test]
    fn default_version_is_0_1_0() {
        let (ad, _) = make_search_ad();
        assert_eq!(ad.version, "0.1.0");
    }

    #[test]
    fn with_version_builder() {
        let (ad, _) = make_search_ad();
        let ad = ad.with_version("2.3.1");
        assert_eq!(ad.version, "2.3.1");
    }

    #[test]
    fn version_included_in_signature() {
        // Two ads that differ only in version must produce different signatures.
        let (ad1, key) = make_search_ad();
        let mut v1 = ad1.clone().with_version("1.0.0");
        v1.sign(&key).unwrap();

        let mut v2 = ad1.with_version("2.0.0");
        v2.sign(&key).unwrap();

        assert_ne!(
            v1.signature, v2.signature,
            "different versions must produce different signatures"
        );
    }

    #[test]
    fn version_survives_json_roundtrip() {
        let (ad, _) = make_search_ad();
        let ad = ad.with_version("3.14.0");
        let json = serde_json::to_string(&ad).unwrap();
        let back: AgentAdvertisement = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, "3.14.0");
    }

    #[test]
    fn absent_version_deserializes_as_default() {
        // Backward compatibility: advertisements from before versioning
        // should deserialize with the default version "0.1.0".
        let json = serde_json::json!({
            "@context": "https://schema.org",
            "@type": "schema:Service",
            "name": "Legacy Agent",
            "provider": {
                "@type": "schema:Organization",
                "name": "Test",
                "did": "did:key:test"
            },
            "capability": ["schema:SearchAction"],
            "object_types": [],
            "requires_disclosure": [],
            "returns": [],
            "ttl_min": 300,
            "signed_by": "did:key:test"
        });
        let ad: AgentAdvertisement = serde_json::from_value(json).unwrap();
        assert_eq!(ad.version, "0.1.0");
    }
}
