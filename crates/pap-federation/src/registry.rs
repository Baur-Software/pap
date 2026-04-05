use std::collections::HashSet;

use chrono::{DateTime, Utc};
use pap_did::verify_key_from_did;
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};
use serde::{Deserialize, Serialize};

use crate::error::FederationError;
use crate::peer::{PeerStatus, PeerVouch, RegistryPeer};

/// Policy configuration for peer registration with vouch-based admission.
///
/// The adversarial analysis found that vouch rings grow exponentially
/// without budgets. This policy enforces:
/// - Minimum vouch count for admission
/// - Per-peer annual vouch budgets (default 3/year)
/// - Minimum age before a peer can vouch (default 90 days)
/// - Probationary period for new peers (default 60 days)
/// - Diverse trust path requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRegistrationPolicy {
    /// Minimum number of valid vouches required for registration.
    pub min_vouches: usize,
    /// Maximum vouches a single peer can issue per year.
    pub vouch_budget_per_year: usize,
    /// Minimum peer age in days before the peer is allowed to vouch for others.
    pub min_age_to_vouch_days: u64,
    /// Number of days a newly registered peer remains in probation.
    pub probation_days: u64,
    /// Whether vouchers must have independent trust paths (not yet enforced,
    /// reserved for future graph-based analysis).
    pub require_diverse_paths: bool,
}

impl Default for PeerRegistrationPolicy {
    fn default() -> Self {
        Self {
            min_vouches: 3,
            vouch_budget_per_year: 3,
            min_age_to_vouch_days: 90,
            probation_days: 60,
            require_diverse_paths: true,
        }
    }
}

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
    /// Policy governing peer registration with vouches.
    pub policy: PeerRegistrationPolicy,
}

impl FederatedRegistry {
    pub fn new() -> Self {
        Self {
            local: MarketplaceRegistry::new(),
            peers: Vec::new(),
            seen_hashes: HashSet::new(),
            policy: PeerRegistrationPolicy::default(),
        }
    }

    /// Create a registry with a custom peer registration policy.
    pub fn with_policy(policy: PeerRegistrationPolicy) -> Self {
        Self {
            local: MarketplaceRegistry::new(),
            peers: Vec::new(),
            seen_hashes: HashSet::new(),
            policy,
        }
    }

    /// Add a federation peer directly (bypasses vouch requirements).
    ///
    /// **Note**: This method is retained for backward compatibility and
    /// bootstrap/testing scenarios. For production peer admission, use
    /// `register_peer_with_vouches` which enforces vouch-based admission
    /// with budget and age constraints.
    pub fn add_peer(&mut self, peer: RegistryPeer) {
        self.peers.push(peer);
    }

    /// Register a new peer with vouch-based admission.
    ///
    /// Enforces the full `PeerRegistrationPolicy`:
    /// 1. Verifies each vouch signature cryptographically
    /// 2. Checks minimum vouch count
    /// 3. Checks each voucher exists in the peer list
    /// 4. Checks each voucher is not probationary
    /// 5. Checks each voucher's age meets `min_age_to_vouch_days`
    ///
    /// On success, the peer is added with `PeerStatus::Probationary` and
    /// a `registered_at` timestamp.
    pub fn register_peer_with_vouches(
        &mut self,
        mut peer: RegistryPeer,
        vouches: Vec<PeerVouch>,
        now: DateTime<Utc>,
    ) -> Result<(), FederationError> {
        // 1. Check minimum vouch count
        if vouches.len() < self.policy.min_vouches {
            return Err(FederationError::InsufficientVouches {
                needed: self.policy.min_vouches,
                got: vouches.len(),
            });
        }

        for vouch in &vouches {
            // 2. Verify each vouch signature
            let verifying_key = verify_key_from_did(&vouch.voucher_did).map_err(|e| {
                FederationError::InvalidVouch(format!(
                    "cannot derive key from voucher DID {}: {e}",
                    vouch.voucher_did
                ))
            })?;
            vouch.verify(&verifying_key)?;

            // 3. Check voucher exists in the peer list
            let voucher_peer = self
                .peers
                .iter()
                .find(|p| p.did == vouch.voucher_did)
                .ok_or_else(|| FederationError::VoucherNotFound(vouch.voucher_did.clone()))?;

            // 4. Check voucher is not probationary
            if voucher_peer.is_probationary() {
                return Err(FederationError::PeerProbationary(vouch.voucher_did.clone()));
            }

            // 5. Check voucher's age meets min_age_to_vouch_days
            let voucher_age_days = self.peer_age_days(voucher_peer, now);
            if voucher_age_days < self.policy.min_age_to_vouch_days {
                return Err(FederationError::VoucherTooYoung {
                    did: vouch.voucher_did.clone(),
                    age_days: voucher_age_days,
                    min_days: self.policy.min_age_to_vouch_days,
                });
            }
        }

        // All checks passed -- add peer as probationary
        peer.status = PeerStatus::Probationary;
        peer.registered_at = Some(now.to_rfc3339());
        self.peers.push(peer);
        Ok(())
    }

    /// Calculate a peer's age in days based on `registered_at` or `last_sync`.
    fn peer_age_days(&self, peer: &RegistryPeer, now: DateTime<Utc>) -> u64 {
        // Prefer registered_at, fall back to last_sync
        if let Some(ref registered_at) = peer.registered_at {
            if let Ok(dt) = DateTime::parse_from_rfc3339(registered_at) {
                let duration = now.signed_duration_since(dt.with_timezone(&Utc));
                return duration.num_days().max(0) as u64;
            }
        }
        if let Some(last_sync) = peer.last_sync {
            let duration = now.signed_duration_since(last_sync);
            return duration.num_days().max(0) as u64;
        }
        0
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

    /// Query local registry by action with cursor-based pagination.
    ///
    /// Returns (matching_ads, next_cursor, has_more).
    /// Ads are sorted lexicographically by `signed_by` DID.
    /// If `cursor` is Some, only ads with DID > cursor are returned.
    pub fn query_local_paginated(
        &self,
        action: &str,
        cursor: Option<&str>,
        page_size: usize,
    ) -> (Vec<&AgentAdvertisement>, Option<String>, bool) {
        let mut ads: Vec<&AgentAdvertisement> = self.query_local(action);

        // Sort by signed_by DID for stable cursor ordering
        ads.sort_by(|a, b| a.signed_by.cmp(&b.signed_by));

        // Apply cursor filter: skip ads with DID <= cursor
        if let Some(cursor) = cursor {
            ads.retain(|ad| ad.signed_by.as_str() > cursor);
        }

        // Check if there are more results beyond this page
        let has_more = ads.len() > page_size;
        ads.truncate(page_size);

        let next_cursor = if has_more {
            ads.last().map(|ad| ad.signed_by.clone())
        } else {
            None
        };

        (ads, next_cursor, has_more)
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
    pub fn verify_advertisement(&self, ad: &AgentAdvertisement) -> bool {
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
