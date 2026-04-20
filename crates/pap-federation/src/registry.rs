use std::collections::{HashMap, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use pap_did::verify_key_from_did;
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};
use serde::{Deserialize, Serialize};

use crate::error::FederationError;
use crate::peer::{PeerStatus, PeerTrustSignals, PeerVouch, RegistryPeer};

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
    /// Whether vouchers must have independent trust paths.
    pub require_diverse_paths: bool,
    /// How many hops up the vouch graph to search for common ancestors (D).
    pub path_diversity_hops: u64,
    /// Reject if any non-genesis, non-voucher intermediate peer appears in this many or
    /// more voucher ancestor chains (K). Minimum useful value: 1 (reject any shared
    /// intermediate). Default: 2. Higher values allow more ancestry overlap.
    pub max_shared_ancestor_vouchers: usize,
}

impl Default for PeerRegistrationPolicy {
    fn default() -> Self {
        Self {
            min_vouches: 3,
            vouch_budget_per_year: 3,
            min_age_to_vouch_days: 90,
            probation_days: 60,
            require_diverse_paths: true,
            path_diversity_hops: 3,
            max_shared_ancestor_vouchers: 2,
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

    /// Add a federation peer directly, bypassing `PeerRegistrationPolicy`.
    ///
    /// **Only use for bootstrapping (first peer) or internal trusted contexts.**
    /// This method skips all vouch verification, budget checks, and path-diversity
    /// requirements. External peer admission must use `register_peer_with_vouches`
    /// so the federation trust model is enforced.
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

        // 6. Require diverse trust paths if the policy demands it.
        if self.policy.require_diverse_paths {
            let voucher_dids: Vec<String> = vouches.iter().map(|v| v.voucher_did.clone()).collect();
            self.check_path_diversity(
                &voucher_dids,
                self.policy.path_diversity_hops,
                self.policy.max_shared_ancestor_vouchers,
            )?;
        }

        // All checks passed -- persist admitted vouches as graph edges, then add as probationary.
        // The stored vouches are required for future path-diversity checks on subsequent registrations.
        match &mut peer.trust_signals {
            Some(ts) => ts.vouches.extend(vouches.iter().cloned()),
            None => {
                peer.trust_signals = Some(PeerTrustSignals {
                    vouches: vouches.clone(),
                    tee_attestation: None,
                    operational_history: None,
                    domain_verification: None,
                });
            }
        }
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

    /// Build a directed vouch graph from stored peer trust signals.
    ///
    /// Returns a map from `vouchee_did` → list of `voucher_did`s extracted
    /// from each peer's `trust_signals.vouches`. Genesis peers (added via
    /// `add_peer`) have no entry as a key since no vouch record admits them.
    fn build_vouch_graph(&self) -> HashMap<String, Vec<String>> {
        let mut graph: HashMap<String, Vec<String>> = HashMap::new();
        for peer in &self.peers {
            if let Some(ts) = &peer.trust_signals {
                for vouch in &ts.vouches {
                    graph
                        .entry(vouch.vouchee_did.clone())
                        .or_default()
                        .push(vouch.voucher_did.clone());
                }
            }
        }
        graph
    }

    /// BFS ancestor traversal of the vouch graph.
    ///
    /// Starting from `start_did`, follows parent edges up to `max_hops` levels.
    /// Returns all reachable ancestor DIDs including `start_did` at hop 0.
    /// Cycles are handled safely via the `visited` set.
    fn ancestors_within_hops(
        start_did: &str,
        graph: &HashMap<String, Vec<String>>,
        max_hops: u64,
    ) -> HashSet<String> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u64)> = VecDeque::new();
        queue.push_back((start_did.to_string(), 0));
        while let Some((current, depth)) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            if depth < max_hops {
                if let Some(parents) = graph.get(&current) {
                    for parent in parents {
                        if !visited.contains(parent) {
                            queue.push_back((parent.clone(), depth + 1));
                        }
                    }
                }
            }
        }
        visited
    }

    /// Check that the candidate's vouchers have independent trust paths.
    ///
    /// Builds the vouch graph from stored peer trust signals, then BFS-traverses
    /// up to `hops` levels from each voucher DID. If any non-genesis peer appears
    /// as an ancestor in `max_shared` or more voucher chains, returns
    /// `FederationError::NonDiversePaths`.
    ///
    /// Genesis peers (those not present as a vouchee in any stored vouch record)
    /// are excluded from the count — all paths eventually converge at trust roots
    /// and counting them would produce false rejections in small networks.
    fn check_path_diversity(
        &self,
        voucher_dids: &[String],
        hops: u64,
        max_shared: usize,
    ) -> Result<(), FederationError> {
        let graph = self.build_vouch_graph();

        // Genesis set: peers whose DID does not appear as a vouchee in any stored vouch.
        let genesis: HashSet<&str> = self
            .peers
            .iter()
            .filter(|p| !graph.contains_key(&p.did))
            .map(|p| p.did.as_str())
            .collect();

        // Compute ancestor sets for each voucher.
        let ancestor_chains: Vec<HashSet<String>> = voucher_dids
            .iter()
            .map(|v| Self::ancestors_within_hops(v, &graph, hops))
            .collect();

        // Count how many chains each non-genesis, non-voucher intermediate appears in.
        // Voucher DIDs are excluded because each voucher naturally appears in its own BFS
        // result (depth 0); counting them would make K=1 reject all non-genesis vouchers.
        let voucher_set: HashSet<&str> = voucher_dids.iter().map(|s| s.as_str()).collect();
        let mut ancestor_count: HashMap<String, usize> = HashMap::new();
        for chain in &ancestor_chains {
            for ancestor in chain {
                if !genesis.contains(ancestor.as_str()) && !voucher_set.contains(ancestor.as_str())
                {
                    *ancestor_count.entry(ancestor.clone()).or_insert(0) += 1;
                }
            }
        }

        // Deterministic error: pick the most-shared violating ancestor (highest count,
        // then lexicographically smallest DID for stable output on ties).
        let violating = ancestor_count
            .iter()
            .filter(|(_, &count)| count >= max_shared)
            .max_by(|(a_did, &a_count), (b_did, &b_count)| {
                a_count.cmp(&b_count).then_with(|| b_did.cmp(a_did))
            });
        if let Some((ancestor, count)) = violating {
            return Err(FederationError::NonDiversePaths {
                common_ancestor: ancestor.clone(),
                voucher_count: *count,
            });
        }

        Ok(())
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

    /// Query local registry by action with an exact version constraint.
    pub fn query_local_versioned(&self, action: &str, version: &str) -> Vec<&AgentAdvertisement> {
        self.local.query_by_action_and_version(action, version)
    }

    /// Query local registry by action, returning only the latest version
    /// per provider DID. Uses semver ordering.
    pub fn query_local_latest(&self, action: &str) -> Vec<&AgentAdvertisement> {
        self.local.query_latest_by_action(action)
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

#[cfg(test)]
impl FederatedRegistry {
    /// Promote a peer from Probationary to Active by DID (test-only).
    ///
    /// The `peers` field is private; this escape hatch allows tests to graduate
    /// intermediate peers so they can vouch for subsequent registrations.
    pub(crate) fn promote_peer_to_active(&mut self, did: &str) {
        if let Some(p) = self.peers.iter_mut().find(|p| p.did == did) {
            p.status = PeerStatus::Active;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::RegistryPeer;
    use pap_test_utils::{did_from_key, make_keypair};

    // ── add_peer bypasses policy ──────────────────────────────────────────────

    /// `add_peer` is documented to bypass `PeerRegistrationPolicy` entirely.
    /// Even with an extremely restrictive policy (min_vouches = 5) the peer
    /// must be added without error.
    #[test]
    fn add_peer_bypasses_policy_regardless_of_policy_settings() {
        let strict_policy = PeerRegistrationPolicy {
            min_vouches: 5,
            ..Default::default()
        };
        let mut registry = FederatedRegistry::with_policy(strict_policy);
        let peer = RegistryPeer::new("did:key:zBypassTest", "https://bypass.example.com");
        // Must not panic or require vouches.
        registry.add_peer(peer);
        assert_eq!(
            registry.peers().len(),
            1,
            "add_peer must admit the peer regardless of policy"
        );
        assert_eq!(registry.peers()[0].did, "did:key:zBypassTest");
    }

    // ── register_peer_with_vouches enforces min_vouches ───────────────────────

    /// Attempting to register with fewer vouches than `min_vouches` must return
    /// `FederationError::InsufficientVouches`.
    #[test]
    fn register_peer_respects_min_vouches_policy() {
        let policy = PeerRegistrationPolicy {
            min_vouches: 2,
            vouch_budget_per_year: 10,
            min_age_to_vouch_days: 0,
            probation_days: 0,
            require_diverse_paths: false,
            path_diversity_hops: 0,
            max_shared_ancestor_vouchers: 10,
        };
        let mut registry = FederatedRegistry::with_policy(policy);

        // Bootstrap one voucher peer so the vouch graph is non-empty.
        let voucher_key = make_keypair();
        let voucher_did = did_from_key(&voucher_key);
        let mut voucher_peer = RegistryPeer::new(&voucher_did, "https://voucher.example.com");
        // Make it Active (not Probationary) and old enough to vouch.
        voucher_peer.status = PeerStatus::Active;
        voucher_peer.registered_at = Some("2000-01-01T00:00:00Z".into());
        registry.add_peer(voucher_peer);

        // Build only 1 vouch, which is below the required 2.
        let candidate_did = "did:key:zCandidate";
        let vouch = crate::peer::PeerVouch::sign(
            &voucher_did,
            candidate_did,
            "2026-01-01T00:00:00Z",
            "direct-interaction",
            &voucher_key,
        );
        let candidate = RegistryPeer::new(candidate_did, "https://candidate.example.com");
        let now = chrono::Utc::now();

        let result = registry.register_peer_with_vouches(candidate, vec![vouch], now);
        match result {
            Err(FederationError::InsufficientVouches { needed, got }) => {
                assert_eq!(needed, 2);
                assert_eq!(got, 1);
            }
            other => panic!("expected InsufficientVouches, got: {other:?}"),
        }
    }

    // ── require_diverse_paths persisted in policy ─────────────────────────────

    /// The `require_diverse_paths` field is documented but its enforcement is
    /// conditional. This test verifies the field round-trips through JSON
    /// serialization so it is not lost if the policy is persisted or logged.
    #[test]
    fn require_diverse_paths_field_is_persisted_in_policy() {
        let policy = PeerRegistrationPolicy {
            require_diverse_paths: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&policy).expect("serialization cannot fail");
        let restored: PeerRegistrationPolicy =
            serde_json::from_str(&json).expect("deserialization cannot fail");
        assert!(
            restored.require_diverse_paths,
            "require_diverse_paths must survive a JSON round-trip"
        );
    }

    // ── peers() count ─────────────────────────────────────────────────────────

    /// An empty registry must report zero peers; after one `add_peer` call it
    /// must report exactly one.
    #[test]
    fn peer_count_method_if_exists() {
        let mut registry = FederatedRegistry::new();
        assert_eq!(
            registry.peers().len(),
            0,
            "fresh registry must have zero peers"
        );
        registry.add_peer(RegistryPeer::new(
            "did:key:zCountTest",
            "https://count.example.com",
        ));
        assert_eq!(
            registry.peers().len(),
            1,
            "registry must have exactly one peer after add_peer"
        );
    }
}
