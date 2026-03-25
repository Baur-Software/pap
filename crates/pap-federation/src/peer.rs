use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
}

impl RegistryPeer {
    pub fn new(did: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            endpoint: endpoint.into(),
            cert_fingerprint: None,
            last_sync: None,
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
        }
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

    #[test]
    fn new_peer_has_no_fingerprint() {
        let peer = RegistryPeer::new("did:key:z1", "https://peer.example.com");
        assert_eq!(peer.did, "did:key:z1");
        assert_eq!(peer.endpoint, "https://peer.example.com");
        assert!(peer.cert_fingerprint.is_none());
        assert!(peer.last_sync.is_none());
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
        // JSON without cert_fingerprint field should deserialize with None
        let json = r#"{"did":"did:key:z1","endpoint":"https://p.com","last_sync":null}"#;
        let peer: RegistryPeer = serde_json::from_str(json).unwrap();
        assert!(peer.cert_fingerprint.is_none());
    }

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
