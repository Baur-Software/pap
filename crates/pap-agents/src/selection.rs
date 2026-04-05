//! Memory-informed agent selection (ISS-630).
//!
//! This module provides the `AgentSelector` trait and two implementations:
//!
//! - `RandomSelector` — baseline random selection used as a fallback or for
//!   testing when no historical data is available.
//! - `MemoryInformedSelector` — prefers agents with higher historical success
//!   rates, falling back to random when no history exists. Ties are broken by
//!   `total_episodes` (more data = more trusted).
//!
//! # Design note
//!
//! `papillon-shared` is intentionally **not** a dependency of `pap-agents`
//! (architectural rule). The caller (Papillon app) converts its
//! `papillon_shared::db::AgentProfile` into `HistoricalProfile` before
//! passing it to `AgentSelectorFactory::build`.

use pap_marketplace::AgentAdvertisement;

// ── Public data types ─────────────────────────────────────────────────────────

/// Minimal historical performance record for a single agent.
///
/// The Papillon app populates this from `papillon_shared::db::AgentProfile`
/// and passes the converted slice to `AgentSelectorFactory::build`.
#[derive(Debug, Clone)]
pub struct HistoricalProfile {
    /// The agent's DID (`did:key:…`).  Matched against
    /// `AgentAdvertisement::signed_by`.
    pub agent_did: String,

    /// Fraction of episodes that succeeded, in the range `[0.0, 1.0]`.
    pub success_rate: f64,

    /// Total number of recorded episodes — used to break ties.
    pub total_episodes: u64,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Select the best agent advertisement from a candidate slice.
///
/// Implementations **must** be `Send + Sync` so selectors can be stored in
/// shared app state (e.g., inside an `Arc`).
pub trait AgentSelector: Send + Sync {
    /// Return the preferred candidate for `action`, or `None` if `candidates`
    /// is empty.
    fn select<'a>(
        &self,
        candidates: &'a [AgentAdvertisement],
        action: &str,
    ) -> Option<&'a AgentAdvertisement>;
}

// ── RandomSelector ────────────────────────────────────────────────────────────

/// Baseline selector that picks a uniformly random candidate.
///
/// Used as a fallback when no historical data is available and as a
/// deterministic stub in unit tests via the seeded variant.
pub struct RandomSelector;

impl AgentSelector for RandomSelector {
    fn select<'a>(
        &self,
        candidates: &'a [AgentAdvertisement],
        _action: &str,
    ) -> Option<&'a AgentAdvertisement> {
        if candidates.is_empty() {
            return None;
        }
        // Use a thread-local random index derived from the standard library's
        // default hasher — no external PRNG crate needed and no novel crypto.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;

        let mut hasher = DefaultHasher::new();
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos()
            .hash(&mut hasher);
        let idx = (hasher.finish() as usize) % candidates.len();
        Some(&candidates[idx])
    }
}

// ── MemoryInformedSelector ────────────────────────────────────────────────────

/// Selector that prefers agents with a higher historical success rate.
///
/// # Selection algorithm
///
/// 1. Filter `candidates` to those that support `action`
///    (`AgentAdvertisement::supports_action`).
/// 2. For each filtered candidate, look up its `HistoricalProfile` by DID
///    (`signed_by` field).
/// 3. Rank by `success_rate` descending; break ties by `total_episodes`
///    descending (more data → more trusted).
/// 4. If no candidate has any historical data, fall back to `RandomSelector`.
pub struct MemoryInformedSelector {
    profiles: Vec<HistoricalProfile>,
    fallback: RandomSelector,
}

impl MemoryInformedSelector {
    /// Create a new selector pre-loaded with historical profiles.
    pub fn new(profiles: Vec<HistoricalProfile>) -> Self {
        Self {
            profiles,
            fallback: RandomSelector,
        }
    }

    /// Look up the historical profile for a given agent DID, if any.
    fn profile_for(&self, agent_did: &str) -> Option<&HistoricalProfile> {
        self.profiles.iter().find(|p| p.agent_did == agent_did)
    }
}

impl AgentSelector for MemoryInformedSelector {
    fn select<'a>(
        &self,
        candidates: &'a [AgentAdvertisement],
        action: &str,
    ) -> Option<&'a AgentAdvertisement> {
        if candidates.is_empty() {
            return None;
        }

        // Filter to candidates that support the requested action.
        let action_candidates: Vec<&AgentAdvertisement> = candidates
            .iter()
            .filter(|ad| ad.supports_action(action))
            .collect();

        // If no candidates support the action, consider all of them (the
        // caller already filtered; this is a safety net).
        let pool: &[&AgentAdvertisement] = if action_candidates.is_empty() {
            // Collect all into a temporary vec; we borrow it below.
            return self.fallback.select(candidates, action);
        } else {
            &action_candidates
        };

        // Determine whether any candidate has historical data.
        let has_history = pool
            .iter()
            .any(|ad| self.profile_for(&ad.signed_by).is_some());

        if !has_history {
            // No data for any candidate — delegate to the random baseline.
            return self.fallback.select(candidates, action);
        }

        // Score each candidate.  Candidates with no profile get a score of
        // (-1.0, 0) so they are always ranked below those with real data.
        pool.iter().copied().max_by(|a, b| {
            let score_a = self
                .profile_for(&a.signed_by)
                .map(|p| (p.success_rate, p.total_episodes))
                .unwrap_or((-1.0, 0));
            let score_b = self
                .profile_for(&b.signed_by)
                .map(|p| (p.success_rate, p.total_episodes))
                .unwrap_or((-1.0, 0));
            // Compare success_rate first, then total_episodes.
            score_a
                .0
                .partial_cmp(&score_b.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(score_a.1.cmp(&score_b.1))
        })
    }
}

// ── Factory ───────────────────────────────────────────────────────────────────

/// Factory that constructs the appropriate `AgentSelector` for a given set of
/// historical profiles.
pub struct AgentSelectorFactory;

impl AgentSelectorFactory {
    /// Build a selector.
    ///
    /// - If `profiles` is non-empty, returns a `MemoryInformedSelector`.
    /// - Otherwise returns a `RandomSelector` (no history available yet).
    pub fn build(profiles: Vec<HistoricalProfile>) -> Box<dyn AgentSelector> {
        if profiles.is_empty() {
            Box::new(RandomSelector)
        } else {
            Box::new(MemoryInformedSelector::new(profiles))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use pap_did::PrincipalKeypair;
    use rand::rngs::OsRng;

    /// Build a minimal signed `AgentAdvertisement` with a generated DID.
    fn make_ad(name: &str, action: &str) -> (AgentAdvertisement, String) {
        let key = SigningKey::generate(&mut OsRng);
        let kp = PrincipalKeypair::from_bytes(&key.to_bytes()).unwrap();
        let did = kp.did();
        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            vec![action.to_string()],
            vec![],
            vec![],
            vec![],
        );
        ad.sign(&key);
        (ad, did)
    }

    // ── RandomSelector ────────────────────────────────────────────────────────

    #[test]
    fn random_selector_empty_returns_none() {
        let sel = RandomSelector;
        assert!(sel.select(&[], "schema:SearchAction").is_none());
    }

    #[test]
    fn random_selector_single_candidate_returns_it() {
        let (ad, _did) = make_ad("Agent A", "schema:SearchAction");
        let candidates = vec![ad];
        let sel = RandomSelector;
        let result = sel.select(&candidates, "schema:SearchAction");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "Agent A");
    }

    #[test]
    fn random_selector_returns_a_candidate_from_the_slice() {
        let (ad_a, _) = make_ad("Agent A", "schema:SearchAction");
        let (ad_b, _) = make_ad("Agent B", "schema:SearchAction");
        let candidates = vec![ad_a, ad_b];
        let sel = RandomSelector;
        let result = sel.select(&candidates, "schema:SearchAction");
        assert!(result.is_some());
        let name = result.unwrap().name.as_str();
        assert!(name == "Agent A" || name == "Agent B");
    }

    // ── MemoryInformedSelector ────────────────────────────────────────────────

    #[test]
    fn memory_selector_empty_candidates_returns_none() {
        let sel = MemoryInformedSelector::new(vec![]);
        assert!(sel.select(&[], "schema:SearchAction").is_none());
    }

    #[test]
    fn memory_selector_no_history_falls_back_to_random() {
        let (ad_a, _) = make_ad("Agent A", "schema:SearchAction");
        let (ad_b, _) = make_ad("Agent B", "schema:SearchAction");
        let candidates = vec![ad_a, ad_b];
        // No profiles — should still return *something*.
        let sel = MemoryInformedSelector::new(vec![]);
        let result = sel.select(&candidates, "schema:SearchAction");
        assert!(result.is_some());
    }

    #[test]
    fn memory_selector_prefers_higher_success_rate() {
        let (ad_a, did_a) = make_ad("Agent A", "schema:SearchAction");
        let (ad_b, did_b) = make_ad("Agent B", "schema:SearchAction");

        let profiles = vec![
            HistoricalProfile {
                agent_did: did_a,
                success_rate: 0.60,
                total_episodes: 100,
            },
            HistoricalProfile {
                agent_did: did_b,
                success_rate: 0.95,
                total_episodes: 50,
            },
        ];

        let candidates = vec![ad_a, ad_b];
        let sel = MemoryInformedSelector::new(profiles);
        let result = sel.select(&candidates, "schema:SearchAction").unwrap();
        // Agent B has a higher success rate; it must be preferred.
        assert_eq!(result.name, "Agent B");
    }

    #[test]
    fn memory_selector_breaks_ties_by_total_episodes() {
        let (ad_a, did_a) = make_ad("Agent A", "schema:SearchAction");
        let (ad_b, did_b) = make_ad("Agent B", "schema:SearchAction");

        // Both have identical success rates; Agent B has more episodes.
        let profiles = vec![
            HistoricalProfile {
                agent_did: did_a,
                success_rate: 0.80,
                total_episodes: 10,
            },
            HistoricalProfile {
                agent_did: did_b,
                success_rate: 0.80,
                total_episodes: 500,
            },
        ];

        let candidates = vec![ad_a, ad_b];
        let sel = MemoryInformedSelector::new(profiles);
        let result = sel.select(&candidates, "schema:SearchAction").unwrap();
        // Agent B has more data — it wins the tie.
        assert_eq!(result.name, "Agent B");
    }

    #[test]
    fn memory_selector_unknown_agent_ranked_below_known() {
        let (ad_a, did_a) = make_ad("Known Agent", "schema:SearchAction");
        let (ad_b, _did_b) = make_ad("Unknown Agent", "schema:SearchAction");

        // Only agent A has a profile.
        let profiles = vec![HistoricalProfile {
            agent_did: did_a,
            success_rate: 0.10, // even a low rate beats no data
            total_episodes: 1,
        }];

        let candidates = vec![ad_a, ad_b];
        let sel = MemoryInformedSelector::new(profiles);
        let result = sel.select(&candidates, "schema:SearchAction").unwrap();
        assert_eq!(result.name, "Known Agent");
    }

    #[test]
    fn memory_selector_filters_by_action() {
        let (ad_search, did_search) = make_ad("Search Agent", "schema:SearchAction");
        let (ad_book, _did_book) = make_ad("Book Agent", "schema:ReserveAction");

        // Only the search agent supports SearchAction.
        let profiles = vec![HistoricalProfile {
            agent_did: did_search,
            success_rate: 0.90,
            total_episodes: 100,
        }];

        let candidates = vec![ad_search, ad_book];
        let sel = MemoryInformedSelector::new(profiles);
        let result = sel.select(&candidates, "schema:SearchAction").unwrap();
        assert_eq!(result.name, "Search Agent");
    }

    // ── AgentSelectorFactory ──────────────────────────────────────────────────

    #[test]
    fn factory_empty_profiles_returns_random() {
        let selector = AgentSelectorFactory::build(vec![]);
        let (ad, _) = make_ad("Agent A", "schema:SearchAction");
        let candidates = vec![ad];
        // Should not panic and should return the single candidate.
        let result = selector.select(&candidates, "schema:SearchAction");
        assert!(result.is_some());
    }

    #[test]
    fn factory_with_profiles_returns_memory_informed() {
        let (ad_a, did_a) = make_ad("Agent A", "schema:SearchAction");
        let (ad_b, did_b) = make_ad("Agent B", "schema:SearchAction");

        let profiles = vec![
            HistoricalProfile {
                agent_did: did_a,
                success_rate: 0.20,
                total_episodes: 200,
            },
            HistoricalProfile {
                agent_did: did_b,
                success_rate: 0.99,
                total_episodes: 200,
            },
        ];

        let selector = AgentSelectorFactory::build(profiles);
        let candidates = vec![ad_a, ad_b];
        let result = selector.select(&candidates, "schema:SearchAction").unwrap();
        // Agent B should win with its higher success rate.
        assert_eq!(result.name, "Agent B");
    }

    #[test]
    fn selector_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RandomSelector>();
        assert_send_sync::<MemoryInformedSelector>();
    }
}
