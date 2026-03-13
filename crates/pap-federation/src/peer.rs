use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A known federation peer (another marketplace registry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPeer {
    /// DID of the peer registry operator.
    pub did: String,

    /// HTTP endpoint for federation API calls.
    pub endpoint: String,

    /// When we last successfully synced with this peer.
    pub last_sync: Option<DateTime<Utc>>,
}

impl RegistryPeer {
    pub fn new(did: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            did: did.into(),
            endpoint: endpoint.into(),
            last_sync: None,
        }
    }
}
