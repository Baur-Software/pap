use pap_core::recovery::RevocationProof;
use pap_marketplace::AgentAdvertisement;
use serde::{Deserialize, Serialize};

#[cfg(feature = "native")]
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

    /// Broadcast a principal DID revocation to federation peers.
    RevocationBroadcast { revocation: Box<RevocationProof> },

    /// Acknowledge a revocation broadcast.
    RevocationAck {
        old_principal_did: String,
        accepted: bool,
    },
}

/// HTTP(S) client for federation operations (native only).
///
/// Two construction modes:
/// - `pinned(peers)` — fingerprint-pinned TLS. Use for all communication
///   with verified peers.
/// - `tofu()` — Trust On First Use. Accepts any cert for bootstrapping
///   new peer connections. Record the fingerprint and switch to `pinned()`
///   for subsequent connections.
///
/// For browser environments, use [`FetchFederationClient`](crate::web_client::FetchFederationClient)
/// instead — it uses the Fetch API and doesn't require TLS pinning.
#[cfg(feature = "native")]
pub struct FederationClient {
    client: reqwest::Client,
}

#[cfg(feature = "native")]
impl FederationClient {
    /// Create a federation client with a custom reqwest client.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Create a client pinned to known peer fingerprints.
    ///
    /// Only connects to servers whose TLS cert SHA-256 fingerprint
    /// matches a peer in the list. Peers without fingerprints are ignored.
    pub fn pinned(peers: &[RegistryPeer]) -> Result<Self, FederationError> {
        let fingerprints: Vec<String> = peers
            .iter()
            .filter_map(|p| p.cert_fingerprint.clone())
            .collect();
        if fingerprints.is_empty() {
            return Err(FederationError::ServerError(
                "no peer fingerprints available for TLS pinning".into(),
            ));
        }
        let client = crate::tls::build_pinned_client(&fingerprints)?;
        Ok(Self { client })
    }

    /// Create a TOFU (Trust On First Use) client for bootstrapping.
    ///
    /// SECURITY: Only use for initial peer discovery. Record the peer's
    /// cert fingerprint and use `pinned()` afterward. Will be replaced
    /// by DNS-based bootstrap (`_pap.hostname` TXT records).
    pub fn tofu() -> Self {
        let client = crate::tls::build_tofu_client().unwrap_or_else(|_| reqwest::Client::new());
        Self { client }
    }

    /// Create a federation client with TOFU settings.
    ///
    /// Equivalent to `tofu()`. Prefer `pinned()` for verified peers.
    pub fn new() -> Self {
        Self::tofu()
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

    /// Fetch a node's identity from its `/federation/identity` endpoint.
    ///
    /// This is the first call when bootstrapping a connection to a new peer.
    /// Returns the node's DID, endpoint, and cert fingerprint so the caller
    /// can verify they're talking to who they think they are.
    pub async fn fetch_identity(
        &self,
        endpoint: &str,
    ) -> Result<crate::peer::NodeIdentityResponse, FederationError> {
        let url = format!("{}/federation/identity", endpoint.trim_end_matches('/'));

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| FederationError::PeerUnreachable(e.to_string()))?;

        resp.json()
            .await
            .map_err(|e| FederationError::SyncFailed(e.to_string()))
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

#[cfg(feature = "native")]
impl Default for FederationClient {
    fn default() -> Self {
        Self::new()
    }
}
