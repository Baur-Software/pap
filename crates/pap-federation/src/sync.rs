use pap_marketplace::AgentAdvertisement;
use serde::{Deserialize, Serialize};

use crate::error::FederationError;
use crate::peer::RegistryPeer;

/// Federation protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum FederationMessage {
    /// Query a peer for agents supporting a given action.
    QueryByAction { action: String },

    /// Response to a query — a list of matching advertisements.
    QueryResponse {
        advertisements: Vec<AgentAdvertisement>,
    },

    /// Announce a new local advertisement to a peer.
    Announce {
        advertisement: Box<AgentAdvertisement>,
    },

    /// Acknowledge an announcement.
    AnnounceAck { hash: String, accepted: bool },

    /// Request a peer's known peer list (for peer discovery).
    PeerList,

    /// Response with the peer's known peers.
    PeerListResponse { peers: Vec<RegistryPeer> },
}

/// HTTP(S) client for federation operations.
///
/// Accepts a pre-configured `reqwest::Client` so the caller can set up
/// TLS cert pinning, custom user-agents, timeouts, etc. Use
/// `tls::build_federation_client()` to get a client configured for
/// self-signed cert acceptance.
pub struct FederationClient {
    client: reqwest::Client,
}

impl FederationClient {
    /// Create a federation client with a custom reqwest client.
    ///
    /// For TLS-pinned connections, pass a client built by
    /// `tls::build_federation_client()`.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Create a federation client with default settings.
    ///
    /// Uses `tls::build_federation_client()` which accepts self-signed certs.
    pub fn new() -> Self {
        let client = crate::tls::build_federation_client()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }

    /// Pull advertisements matching an action from a peer.
    pub async fn sync_action(
        &self,
        peer: &RegistryPeer,
        action: &str,
    ) -> Result<Vec<AgentAdvertisement>, FederationError> {
        let url = format!(
            "{}/federation/query?action={}",
            peer.endpoint.trim_end_matches('/'),
            action
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| FederationError::PeerUnreachable(e.to_string()))?;

        let msg: FederationMessage = resp
            .json()
            .await
            .map_err(|e| FederationError::SyncFailed(e.to_string()))?;

        match msg {
            FederationMessage::QueryResponse { advertisements } => Ok(advertisements),
            _ => Err(FederationError::SyncFailed(
                "unexpected response type".into(),
            )),
        }
    }

    /// Announce a local advertisement to a peer.
    pub async fn announce(
        &self,
        peer: &RegistryPeer,
        ad: &AgentAdvertisement,
    ) -> Result<bool, FederationError> {
        let url = format!(
            "{}/federation/announce",
            peer.endpoint.trim_end_matches('/')
        );

        let msg = FederationMessage::Announce {
            advertisement: Box::new(ad.clone()),
        };

        let resp = self
            .client
            .post(&url)
            .json(&msg)
            .send()
            .await
            .map_err(|e| FederationError::PeerUnreachable(e.to_string()))?;

        let ack: FederationMessage = resp
            .json()
            .await
            .map_err(|e| FederationError::SyncFailed(e.to_string()))?;

        match ack {
            FederationMessage::AnnounceAck { accepted, .. } => Ok(accepted),
            _ => Err(FederationError::SyncFailed("unexpected ack type".into())),
        }
    }

    /// Discover peers known to a given peer.
    pub async fn discover_peers(
        &self,
        peer: &RegistryPeer,
    ) -> Result<Vec<RegistryPeer>, FederationError> {
        let url = format!("{}/federation/peers", peer.endpoint.trim_end_matches('/'));

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| FederationError::PeerUnreachable(e.to_string()))?;

        let msg: FederationMessage = resp
            .json()
            .await
            .map_err(|e| FederationError::SyncFailed(e.to_string()))?;

        match msg {
            FederationMessage::PeerListResponse { peers } => Ok(peers),
            _ => Err(FederationError::SyncFailed(
                "unexpected response type".into(),
            )),
        }
    }
}

impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}
