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
