use std::collections::HashSet;

use pap_did::verify_key_from_did;
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
    pub fn register_local(&mut self, ad: AgentAdvertisement) -> Result<(), FederationError> {
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
    /// Deduplicates by content hash. Validates cryptographic signatures.
    /// Unsigned or invalidly-signed advertisements are rejected.
    /// Returns the number of new advertisements actually merged.
    pub fn merge_remote(&mut self, advertisements: Vec<AgentAdvertisement>) -> usize {
        let mut merged = 0;
        for ad in advertisements {
            let hash = ad.hash();
            if self.seen_hashes.contains(&hash) {
                continue;
            }

            // Verify the advertisement's cryptographic signature
            if !self.verify_advertisement(&ad) {
                continue;
            }

            if self.local.register(ad).is_ok() {
                self.seen_hashes.insert(hash);
                merged += 1;
            }
        }
        merged
    }

    /// Verify an advertisement's Ed25519 signature.
    ///
    /// The signature must match the advertised DID's public key.
    fn verify_advertisement(&self, ad: &AgentAdvertisement) -> bool {
        // Extract the signing DID
        let did = &ad.signed_by;

        // Attempt to derive the verifying key from the DID
        // DIDs are multibase-encoded public keys, so this is a direct extraction
        let verifying_key = match verify_key_from_did(did) {
            Ok(key) => key,
            Err(_) => return false, // Invalid DID
        };

        // Verify the signature cryptographically
        ad.verify(&verifying_key).is_ok()
    }

    /// Return all advertisements (for serving to federation peers).
    pub fn all_advertisements(&self) -> &[AgentAdvertisement] {
        self.local.all()
    }

    /// Remove an advertisement by content hash. Returns true if removed.
    pub fn remove_by_hash(&mut self, hash: &str) -> bool {
        if self.local.remove_by_hash(hash) {
            self.seen_hashes.remove(hash);
            true
        } else {
            false
        }
    }

    /// Remove a federation peer by DID. Returns true if removed.
    pub fn remove_peer(&mut self, did: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.did != did);
        self.peers.len() < before
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
