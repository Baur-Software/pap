use std::collections::HashSet;

use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};

use crate::error::FederationError;
use crate::peer::RegistryPeer;

/// A federated registry wrapping a local `MarketplaceRegistry` with
/// peer awareness and deduplication.
///
/// Advertisements from remote peers are merged into the local registry
/// after signature verification and dedup by content hash. The local
/// registry's query methods work identically — federation is transparent
/// to the query caller.
pub struct FederatedRegistry {
    local: MarketplaceRegistry,
    peers: Vec<RegistryPeer>,
    seen_hashes: HashSet<String>,
}

impl FederatedRegistry {
    pub fn new() -> Self {
        Self {
            local: MarketplaceRegistry::new(),
            peers: Vec::new(),
            seen_hashes: HashSet::new(),
        }
    }

    /// Add a federation peer.
    pub fn add_peer(&mut self, peer: RegistryPeer) {
        self.peers.push(peer);
    }

    /// List known peers.
    pub fn peers(&self) -> &[RegistryPeer] {
        &self.peers
    }

    /// Register a local advertisement (same as `MarketplaceRegistry::register`
    /// but also tracks the hash for dedup).
    pub fn register_local(
        &mut self,
        ad: AgentAdvertisement,
    ) -> Result<(), FederationError> {
        let hash = ad.hash();
        if self.seen_hashes.contains(&hash) {
            return Err(FederationError::DuplicateAdvertisement(hash));
        }
        self.local
            .register(ad)
            .map_err(|e| FederationError::InvalidAdvertisement(e.to_string()))?;
        self.seen_hashes.insert(hash);
        Ok(())
    }

    /// Query local registry by action type.
    pub fn query_local(&self, action: &str) -> Vec<&AgentAdvertisement> {
        self.local.query_by_action(action)
    }

    /// Query local registry by action type + disclosure satisfiability.
    pub fn query_local_satisfiable(
        &self,
        action: &str,
        available_properties: &[String],
    ) -> Vec<&AgentAdvertisement> {
        self.local.query_satisfiable(action, available_properties)
    }

    /// Merge remote advertisements into the local registry.
    ///
    /// Deduplicates by content hash. Unsigned advertisements are rejected.
    /// Returns the number of new advertisements actually merged.
    pub fn merge_remote(
        &mut self,
        advertisements: Vec<AgentAdvertisement>,
    ) -> usize {
        let mut merged = 0;
        for ad in advertisements {
            let hash = ad.hash();
            if self.seen_hashes.contains(&hash) {
                continue;
            }
            if ad.signature.is_none() {
                continue;
            }
            if self.local.register(ad).is_ok() {
                self.seen_hashes.insert(hash);
                merged += 1;
            }
        }
        merged
    }

    /// Return all advertisements (for serving to federation peers).
    pub fn all_advertisements(&self) -> &[AgentAdvertisement] {
        self.local.all()
    }

    pub fn len(&self) -> usize {
        self.local.len()
    }

    pub fn is_empty(&self) -> bool {
        self.local.is_empty()
    }
}

impl Default for FederatedRegistry {
    fn default() -> Self {
        Self::new()
    }
}
