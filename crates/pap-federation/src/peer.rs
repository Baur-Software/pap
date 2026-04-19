use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use pap_did::SignatureAlgorithm;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::FederationError;

/// Status of a peer in the federation registry.
///
/// New peers enter as `Probationary` for a configurable period before
/// becoming `Active`. Peers can be `Suspended` for policy violations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PeerStatus {
    /// Newly registered peer within its probationary period.
    Probationary,
    /// Fully trusted peer that has completed probation.
    Active,
    /// Peer suspended for policy violations or adversarial behavior.
    Suspended,
}

/// A signed vouch from one peer attesting to the trustworthiness of another.
///
/// Vouches are one of the four trust signals in the multi-signal defense-in-depth
/// model. Each vouch is cryptographically signed by the voucher's Ed25519 key
/// and contains a structured justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerVouch {
    /// DID of the peer issuing the vouch.
    pub voucher_did: String,
    /// DID of the peer being vouched for.
    pub vouchee_did: String,
    /// When this vouch was issued (RFC 3339).
    pub timestamp: String,
    /// Structured reason for the vouch (e.g., "operational-history", "direct-interaction").
    pub justification: String,
    /// Signature algorithm used. Defaults to Ed25519 for backward compatibility.
    #[serde(default)]
    pub algorithm: SignatureAlgorithm,
    /// Signature by the voucher over the canonical vouch bytes (base64url-encoded).
    pub signature: String,
}

impl PeerVouch {
    /// Sign a new vouch with the voucher's Ed25519 signing key.
    ///
    /// Produces a `PeerVouch` with a valid signature over the canonical
    /// representation of the vouch fields (voucher_did, vouchee_did,
    /// timestamp, justification).
    pub fn sign(
        voucher_did: impl Into<String>,
        vouchee_did: impl Into<String>,
        timestamp: impl Into<String>,
        justification: impl Into<String>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let voucher_did = voucher_did.into();
        let vouchee_did = vouchee_did.into();
        let timestamp = timestamp.into();
        let justification = justification.into();

        let canonical =
            Self::canonical_bytes_static(&voucher_did, &vouchee_did, &timestamp, &justification);
        let sig = signing_key.sign(&canonical);
        use base64::Engine;
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

        Self {
            voucher_did,
            vouchee_did,
            timestamp,
            justification,
            algorithm: SignatureAlgorithm::default(),
            signature,
        }
    }

    /// Verify this vouch's Ed25519 signature against the voucher's public key.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), FederationError> {
        use base64::Engine;
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| {
                FederationError::InvalidVouch(format!("invalid signature encoding: {e}"))
            })?;
        let signature = Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| FederationError::InvalidVouch("invalid signature length".into()))?,
        );
        let canonical = self.canonical_bytes();
        verifying_key
            .verify_strict(&canonical, &signature)
            .map_err(|_| FederationError::InvalidVouch("signature verification failed".into()))
    }

    /// Canonical bytes for this vouch (used for signing/verification).
    fn canonical_bytes(&self) -> Vec<u8> {
        Self::canonical_bytes_static(
            &self.voucher_did,
            &self.vouchee_did,
            &self.timestamp,
            &self.justification,
        )
    }

    /// Canonical bytes from individual fields (used by `sign()` before struct exists).
    fn canonical_bytes_static(
        voucher_did: &str,
        vouchee_did: &str,
        timestamp: &str,
        justification: &str,
    ) -> Vec<u8> {
        let canonical = serde_json::json!({
            "voucher_did": voucher_did,
            "vouchee_did": vouchee_did,
            "timestamp": timestamp,
            "justification": justification,
        });
        serde_json::to_vec(&canonical).expect("canonical serialization cannot fail")
    }

    /// SHA-256 hex digest of the canonical form (useful for dedup).
    pub fn hash(&self) -> String {
        let bytes = self.canonical_bytes();
        let digest = Sha256::digest(&bytes);
        hex::encode(digest)
    }
}

/// Observable operational metrics for a peer, used as a trust signal.
///
/// These metrics are self-reported by the peer but can be cross-validated
/// through federation sync observations. Gross misrepresentation is
/// detectable over time by comparing reported values with observed behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationalHistory {
    /// Days the peer has been continuously online.
    pub uptime_days: u64,
    /// Total advertisements served through this peer.
    pub advertisements_served: u64,
    /// Fraction of successful federation syncs (0.0 to 1.0).
    pub sync_success_rate: f64,
    /// When this peer was first observed (RFC 3339).
    pub first_seen: String,
}

/// DNS/TLS domain verification proof for a peer.
///
/// Proves the peer controls a particular domain, adding a layer of
/// accountability beyond pure DID-based identity. Verification methods
/// include DNS TXT records or TLS SAN fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVerification {
    /// The domain being verified (e.g., "federation.example.com").
    pub domain: String,
    /// How the domain was verified (e.g., "dns-txt", "tls-san").
    pub verification_method: String,
    /// When the verification was performed (RFC 3339).
    pub verified_at: String,
}

/// Multi-signal trust evidence for a federation peer.
///
/// The adversarial analysis found that social vouching alone is insufficient --
/// vouch rings break at 3 colluders. This struct bundles four independent
/// trust signals for defense-in-depth:
///
/// 1. **Vouches** -- signed attestations from existing peers
/// 2. **TEE attestation** -- hardware attestation evidence (opaque hash, verified separately)
/// 3. **Operational history** -- observable metrics that build trust over time
/// 4. **Domain verification** -- DNS/TLS proof of domain control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerTrustSignals {
    /// Signed vouches from existing federation peers.
    pub vouches: Vec<PeerVouch>,
    /// TEE attestation evidence hash (opaque to federation, verified by TEE verifier).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_attestation: Option<String>,
    /// Observable operational metrics for the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operational_history: Option<OperationalHistory>,
    /// DNS/TLS domain verification proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_verification: Option<DomainVerification>,
}

/// A known federation peer (another marketplace registry).
///
/// The `cert_fingerprint` is the SHA-256 hex digest of the peer's
/// DER-encoded TLS certificate. When connecting, the client verifies
/// the server cert against this fingerprint — no CA in the trust chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPeer {
    /// DID of the peer registry operator.
    pub did: String,

    /// HTTPS endpoint for federation API calls.
    pub endpoint: String,

    /// SHA-256 hex fingerprint of the peer's TLS certificate.
    /// Used for certificate pinning — DIDs are the trust root, not CAs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_fingerprint: Option<String>,

    /// When we last successfully synced with this peer.
    pub last_sync: Option<DateTime<Utc>>,

    /// Multi-signal trust evidence for this peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_signals: Option<PeerTrustSignals>,

    /// Current status of this peer in the federation.
    #[serde(default = "default_peer_status")]
    pub status: PeerStatus,

    /// When this peer was registered (RFC 3339). Used for age calculations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_at: Option<String>,
}

fn default_peer_status() -> PeerStatus {
    PeerStatus::Active
}

impl RegistryPeer {
    pub fn new(did: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            endpoint: endpoint.into(),
            cert_fingerprint: None,
            last_sync: None,
            trust_signals: None,
            status: PeerStatus::Active,
            registered_at: None,
        }
    }

    /// Create a peer with a pinned TLS certificate fingerprint.
    pub fn with_fingerprint(
        did: impl Into<String>,
        endpoint: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            did: did.into(),
            endpoint: endpoint.into(),
            cert_fingerprint: Some(fingerprint.into()),
            last_sync: None,
            trust_signals: None,
            status: PeerStatus::Active,
            registered_at: None,
        }
    }

    /// Attach multi-signal trust evidence to this peer.
    pub fn with_trust_signals(mut self, signals: PeerTrustSignals) -> Self {
        self.trust_signals = Some(signals);
        self
    }

    /// Returns true if this peer is in its probationary period.
    pub fn is_probationary(&self) -> bool {
        self.status == PeerStatus::Probationary
    }
}

/// A node's identity as returned by `GET /federation/identity`.
///
/// A connecting node calls this endpoint to learn who it's talking to
/// before trusting anything else. The `cert_fingerprint` is verified
/// against the TLS connection's actual certificate (native clients)
/// or trusted via HTTPS CA chain (browser clients).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentityResponse {
    pub did: String,
    pub endpoint: String,
    pub cert_fingerprint: String,
    pub agent_count: usize,
    pub peer_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pap_test_utils::{did_from_key, make_keypair};

    // --- RegistryPeer backward-compatibility tests ---

    #[test]
    fn new_peer_has_no_fingerprint() {
        let peer = RegistryPeer::new("did:key:z1", "https://peer.example.com");
        assert_eq!(peer.did, "did:key:z1");
        assert_eq!(peer.endpoint, "https://peer.example.com");
        assert!(peer.cert_fingerprint.is_none());
        assert!(peer.last_sync.is_none());
        assert!(peer.trust_signals.is_none());
        assert_eq!(peer.status, PeerStatus::Active);
        assert!(peer.registered_at.is_none());
    }

    #[test]
    fn with_fingerprint_stores_fingerprint() {
        let peer = RegistryPeer::with_fingerprint(
            "did:key:z1",
            "https://peer.example.com",
            "abc123def456",
        );
        assert_eq!(peer.did, "did:key:z1");
        assert_eq!(peer.cert_fingerprint, Some("abc123def456".into()));
        assert!(peer.last_sync.is_none());
        assert_eq!(peer.status, PeerStatus::Active);
    }

    #[test]
    fn peer_serialization_omits_none_fingerprint() {
        let peer = RegistryPeer::new("did:key:z1", "https://peer.example.com");
        let json = serde_json::to_string(&peer).unwrap();
        // cert_fingerprint should be skipped when None
        assert!(!json.contains("cert_fingerprint"));
    }

    #[test]
    fn peer_serialization_includes_fingerprint() {
        let peer = RegistryPeer::with_fingerprint("did:key:z1", "https://p.com", "fp123");
        let json = serde_json::to_string(&peer).unwrap();
        assert!(json.contains("cert_fingerprint"));
        assert!(json.contains("fp123"));
    }

    #[test]
    fn peer_deserialization_missing_fingerprint() {
        // JSON without cert_fingerprint field should deserialize with None;
        // status defaults to Active when missing
        let json = r#"{"did":"did:key:z1","endpoint":"https://p.com","last_sync":null}"#;
        let peer: RegistryPeer = serde_json::from_str(json).unwrap();
        assert!(peer.cert_fingerprint.is_none());
        assert_eq!(peer.status, PeerStatus::Active);
        assert!(peer.trust_signals.is_none());
    }

    // --- RegistryPeer: new fields ---

    #[test]
    fn with_trust_signals_builder() {
        let signals = PeerTrustSignals {
            vouches: vec![],
            tee_attestation: Some("tee-hash-abc".into()),
            operational_history: None,
            domain_verification: None,
        };
        let peer = RegistryPeer::new("did:key:z1", "https://p.com").with_trust_signals(signals);
        assert!(peer.trust_signals.is_some());
        assert_eq!(
            peer.trust_signals.as_ref().unwrap().tee_attestation,
            Some("tee-hash-abc".into())
        );
    }

    #[test]
    fn is_probationary_true_for_probationary_peers() {
        let mut peer = RegistryPeer::new("did:key:z1", "https://p.com");
        peer.status = PeerStatus::Probationary;
        assert!(peer.is_probationary());
    }

    #[test]
    fn is_probationary_false_for_active_peers() {
        let peer = RegistryPeer::new("did:key:z1", "https://p.com");
        assert!(!peer.is_probationary());
    }

    // --- PeerVouch sign/verify ---

    /// Parameterized vouch sign/verify test body.
    fn vouch_sign_verify_for_algorithm(algorithm: pap_did::SignatureAlgorithm) {
        assert_eq!(algorithm, pap_did::SignatureAlgorithm::Ed25519);
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);
        let vouchee_did = "did:key:zVouchee";

        let vouch = PeerVouch::sign(
            &voucher_did,
            vouchee_did,
            "2026-01-15T12:00:00Z",
            "direct-interaction",
            &voucher_key,
        );

        assert_eq!(vouch.voucher_did, voucher_did);
        assert_eq!(vouch.vouchee_did, vouchee_did);
        assert_eq!(vouch.algorithm, algorithm);

        let verifying_key = pap_did::verify_key_from_did(&voucher_did).unwrap();
        assert!(vouch.verify(&verifying_key).is_ok());
    }

    #[test]
    fn vouch_sign_and_verify() {
        vouch_sign_verify_for_algorithm(pap_did::SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn vouch_verify_rejects_wrong_key() {
        let voucher_key = make_keypair();
        let wrong_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);

        let vouch = PeerVouch::sign(
            &voucher_did,
            "did:key:zVouchee",
            "2026-01-15T12:00:00Z",
            "direct-interaction",
            &voucher_key,
        );

        // Verify with wrong key should fail
        assert!(vouch.verify(&wrong_key.verifying_key()).is_err());
    }

    #[test]
    fn vouch_verify_detects_tampering() {
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);

        let mut vouch = PeerVouch::sign(
            &voucher_did,
            "did:key:zVouchee",
            "2026-01-15T12:00:00Z",
            "direct-interaction",
            &voucher_key,
        );

        // Tamper with the justification
        vouch.justification = "tampered-reason".into();

        let verifying_key = pap_did::verify_key_from_did(&voucher_did).unwrap();
        assert!(vouch.verify(&verifying_key).is_err());
    }

    #[test]
    fn vouch_hash_is_stable() {
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);

        let vouch = PeerVouch::sign(
            &voucher_did,
            "did:key:zVouchee",
            "2026-01-15T12:00:00Z",
            "direct-interaction",
            &voucher_key,
        );

        let h1 = vouch.hash();
        let h2 = vouch.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn vouch_serialization_roundtrip() {
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);

        let vouch = PeerVouch::sign(
            &voucher_did,
            "did:key:zVouchee",
            "2026-01-15T12:00:00Z",
            "operational-history",
            &voucher_key,
        );

        let json = serde_json::to_string(&vouch).unwrap();
        let restored: PeerVouch = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.voucher_did, voucher_did);
        assert_eq!(restored.justification, "operational-history");

        // Restored vouch should still verify
        let verifying_key = pap_did::verify_key_from_did(&voucher_did).unwrap();
        assert!(restored.verify(&verifying_key).is_ok());
    }

    // --- OperationalHistory ---

    #[test]
    fn operational_history_serialization_roundtrip() {
        let history = OperationalHistory {
            uptime_days: 365,
            advertisements_served: 50_000,
            sync_success_rate: 0.997,
            first_seen: "2025-01-01T00:00:00Z".into(),
        };

        let json = serde_json::to_string(&history).unwrap();
        let restored: OperationalHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.uptime_days, 365);
        assert_eq!(restored.advertisements_served, 50_000);
        assert!((restored.sync_success_rate - 0.997).abs() < f64::EPSILON);
        assert_eq!(restored.first_seen, "2025-01-01T00:00:00Z");
    }

    // --- DomainVerification ---

    #[test]
    fn domain_verification_serialization_roundtrip() {
        let dv = DomainVerification {
            domain: "federation.example.com".into(),
            verification_method: "dns-txt".into(),
            verified_at: "2026-03-01T10:00:00Z".into(),
        };

        let json = serde_json::to_string(&dv).unwrap();
        let restored: DomainVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.domain, "federation.example.com");
        assert_eq!(restored.verification_method, "dns-txt");
    }

    // --- PeerTrustSignals ---

    #[test]
    fn trust_signals_full_roundtrip() {
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);

        let vouch = PeerVouch::sign(
            &voucher_did,
            "did:key:zVouchee",
            "2026-01-15T12:00:00Z",
            "direct-interaction",
            &voucher_key,
        );

        let signals = PeerTrustSignals {
            vouches: vec![vouch],
            tee_attestation: Some("sha256:abc123".into()),
            operational_history: Some(OperationalHistory {
                uptime_days: 100,
                advertisements_served: 5000,
                sync_success_rate: 0.99,
                first_seen: "2025-06-01T00:00:00Z".into(),
            }),
            domain_verification: Some(DomainVerification {
                domain: "node.example.com".into(),
                verification_method: "tls-san".into(),
                verified_at: "2026-02-15T08:00:00Z".into(),
            }),
        };

        let json = serde_json::to_string(&signals).unwrap();
        let restored: PeerTrustSignals = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.vouches.len(), 1);
        assert!(restored.tee_attestation.is_some());
        assert!(restored.operational_history.is_some());
        assert!(restored.domain_verification.is_some());
    }

    #[test]
    fn trust_signals_omits_none_fields() {
        let signals = PeerTrustSignals {
            vouches: vec![],
            tee_attestation: None,
            operational_history: None,
            domain_verification: None,
        };

        let json = serde_json::to_string(&signals).unwrap();
        assert!(!json.contains("tee_attestation"));
        assert!(!json.contains("operational_history"));
        assert!(!json.contains("domain_verification"));
    }

    // --- PeerStatus ---

    #[test]
    fn peer_status_serialization_roundtrip() {
        for status in [
            PeerStatus::Probationary,
            PeerStatus::Active,
            PeerStatus::Suspended,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let restored: PeerStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    // --- NodeIdentityResponse ---

    #[test]
    fn node_identity_response_serialization_roundtrip() {
        let identity = NodeIdentityResponse {
            did: "did:key:z123".into(),
            endpoint: "https://node.example.com:7890".into(),
            cert_fingerprint: "abcdef0123456789".into(),
            agent_count: 42,
            peer_count: 7,
        };

        let json = serde_json::to_string(&identity).unwrap();
        let restored: NodeIdentityResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.did, "did:key:z123");
        assert_eq!(restored.endpoint, "https://node.example.com:7890");
        assert_eq!(restored.cert_fingerprint, "abcdef0123456789");
        assert_eq!(restored.agent_count, 42);
        assert_eq!(restored.peer_count, 7);
    }

    #[test]
    fn node_identity_response_clone() {
        let identity = NodeIdentityResponse {
            did: "did:key:z1".into(),
            endpoint: "https://n.com".into(),
            cert_fingerprint: "fp".into(),
            agent_count: 1,
            peer_count: 2,
        };
        let cloned = identity.clone();
        assert_eq!(identity.did, cloned.did);
        assert_eq!(identity.agent_count, cloned.agent_count);
    }
}
