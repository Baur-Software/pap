use crate::advertisement::{AgentAdvertisement, OperatorMetrics};
use crate::MarketplaceError;

/// Local file-based marketplace registry for the PoC.
/// Stores agent advertisements in memory and supports querying
/// by Schema.org action type.
pub struct MarketplaceRegistry {
    advertisements: Vec<AgentAdvertisement>,
}

impl MarketplaceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            advertisements: vec![],
        }
    }

    /// Register an agent advertisement.
    pub fn register(&mut self, ad: AgentAdvertisement) -> Result<(), MarketplaceError> {
        if ad.signature.is_none() {
            return Err(MarketplaceError::InvalidAdvertisement(
                "advertisement must be signed".into(),
            ));
        }
        self.advertisements.push(ad);
        Ok(())
    }

    /// Query for agents that support a given Schema.org action type.
    ///
    /// Results are returned in insertion order. This method MUST NOT rank,
    /// sort, or filter by operator metrics. Ranking is the principal's
    /// responsibility.
    pub fn query_by_action(&self, action: &str) -> Vec<&AgentAdvertisement> {
        self.advertisements
            .iter()
            .filter(|ad| ad.supports_action(action))
            .collect()
    }

    /// Query for agents that support a given action AND whose disclosure
    /// requirements can be satisfied by the available properties.
    ///
    /// Results are returned in insertion order. This method MUST NOT rank,
    /// sort, or filter by operator metrics. Ranking is the principal's
    /// responsibility.
    pub fn query_satisfiable(
        &self,
        action: &str,
        available_properties: &[String],
    ) -> Vec<&AgentAdvertisement> {
        self.advertisements
            .iter()
            .filter(|ad| {
                ad.supports_action(action) && ad.disclosure_satisfiable(available_properties)
            })
            .collect()
    }

    /// Query for satisfiable advertisements with their metrics attached.
    ///
    /// This is functionally identical to [`query_satisfiable`] but the name
    /// makes the intent clear: principals receive both advertisements and
    /// raw metrics so they can apply their own trust evaluation locally.
    ///
    /// Results are returned in insertion order. This method MUST NOT rank,
    /// sort, or filter by operator metrics. Ranking is the principal's
    /// responsibility.
    pub fn query_with_metrics(
        &self,
        action: &str,
        available_properties: &[&str],
    ) -> Vec<&AgentAdvertisement> {
        let owned: Vec<String> = available_properties.iter().map(|s| s.to_string()).collect();
        self.advertisements
            .iter()
            .filter(|ad| ad.supports_action(action) && ad.disclosure_satisfiable(&owned))
            .collect()
    }

    /// Query for agents by action, returning each advertisement paired with
    /// its optional operator metrics as a tuple.
    ///
    /// This allows principals to evaluate raw metrics alongside advertisement
    /// data without the marketplace making any ranking decisions.
    ///
    /// Results are returned in insertion order. This method MUST NOT rank,
    /// sort, or filter by operator metrics. Ranking is the principal's
    /// responsibility.
    pub fn query_by_action_and_metrics(
        &self,
        action: &str,
    ) -> Vec<(&AgentAdvertisement, Option<&OperatorMetrics>)> {
        self.advertisements
            .iter()
            .filter(|ad| ad.supports_action(action))
            .map(|ad| (ad, ad.metrics.as_ref()))
            .collect()
    }

    /// Number of registered advertisements.
    pub fn len(&self) -> usize {
        self.advertisements.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.advertisements.is_empty()
    }

    /// All registered advertisements.
    pub fn all(&self) -> &[AgentAdvertisement] {
        &self.advertisements
    }

    /// Remove an advertisement by its content hash. Returns true if found and removed.
    pub fn remove_by_hash(&mut self, hash: &str) -> bool {
        let before = self.advertisements.len();
        self.advertisements.retain(|ad| ad.hash() != hash);
        self.advertisements.len() < before
    }
}

impl Default for MarketplaceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_signed_ad(
        name: &str,
        capabilities: Vec<String>,
        requires_disclosure: Vec<String>,
    ) -> AgentAdvertisement {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            capabilities,
            vec![],
            requires_disclosure,
            vec!["schema:SearchResult".into()],
        );
        ad.sign(&key);
        ad
    }

    #[test]
    fn register_and_query() {
        let mut registry = MarketplaceRegistry::new();

        let search_ad = make_signed_ad("Search Agent", vec!["schema:SearchAction".into()], vec![]);
        let pay_ad = make_signed_ad(
            "Payment Agent",
            vec!["schema:PayAction".into()],
            vec!["schema:Person.name".into()],
        );

        registry.register(search_ad).unwrap();
        registry.register(pay_ad).unwrap();

        let results = registry.query_by_action("schema:SearchAction");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Search Agent");

        let results = registry.query_by_action("schema:PayAction");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Payment Agent");

        let results = registry.query_by_action("schema:ReserveAction");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn query_satisfiable_filters_disclosure() {
        let mut registry = MarketplaceRegistry::new();

        let search_ad = make_signed_ad(
            "Open Search",
            vec!["schema:SearchAction".into()],
            vec![], // no disclosure needed
        );
        let restricted_ad = make_signed_ad(
            "Restricted Search",
            vec!["schema:SearchAction".into()],
            vec!["schema:Person.name".into()], // needs name
        );

        registry.register(search_ad).unwrap();
        registry.register(restricted_ad).unwrap();

        // With no available properties, only Open Search should match
        let results = registry.query_satisfiable("schema:SearchAction", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Open Search");

        // With name available, both should match
        let results =
            registry.query_satisfiable("schema:SearchAction", &["schema:Person.name".into()]);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn reject_unsigned_advertisement() {
        let mut registry = MarketplaceRegistry::new();
        let ad = AgentAdvertisement::new(
            "Unsigned Agent",
            "Corp",
            "did:key:zunsigned",
            vec!["schema:SearchAction".into()],
            vec![],
            vec![],
            vec![],
        );
        assert!(registry.register(ad).is_err());
    }

    #[test]
    fn registry_len() {
        let mut registry = MarketplaceRegistry::new();
        assert!(registry.is_empty());

        let ad = make_signed_ad("Agent", vec!["schema:SearchAction".into()], vec![]);
        registry.register(ad).unwrap();
        assert_eq!(registry.len(), 1);
    }

    fn make_signed_ad_with_metrics(
        name: &str,
        capabilities: Vec<String>,
        requires_disclosure: Vec<String>,
        metrics: OperatorMetrics,
    ) -> AgentAdvertisement {
        let key = SigningKey::generate(&mut OsRng);
        let did = pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
            .unwrap()
            .did();

        let mut ad = AgentAdvertisement::new(
            name,
            "TestCorp",
            &did,
            capabilities,
            vec![],
            requires_disclosure,
            vec!["schema:SearchResult".into()],
        );
        ad.sign(&key);
        ad.with_metrics(metrics)
    }

    fn low_metrics() -> OperatorMetrics {
        OperatorMetrics {
            total_receipts: 5,
            bilateral_attestations: 2,
            unique_counterparties: 1,
            action_types: vec!["schema:SearchAction".into()],
            tee_sessions_pct: 0.1,
            first_seen: Some("2026-03-01T00:00:00Z".into()),
            uptime_days: 3,
        }
    }

    fn high_metrics() -> OperatorMetrics {
        OperatorMetrics {
            total_receipts: 50000,
            bilateral_attestations: 45000,
            unique_counterparties: 8000,
            action_types: vec![
                "schema:SearchAction".into(),
                "schema:PayAction".into(),
                "schema:ReserveAction".into(),
            ],
            tee_sessions_pct: 0.99,
            first_seen: Some("2024-01-01T00:00:00Z".into()),
            uptime_days: 800,
        }
    }

    #[test]
    fn query_by_action_preserves_insertion_order() {
        // Register ads in a specific order and verify query returns them
        // in the same insertion order, regardless of metrics.
        let mut registry = MarketplaceRegistry::new();

        // Insert low-metrics agent first, high-metrics agent second
        let ad_low = make_signed_ad_with_metrics(
            "Low-Volume Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            low_metrics(),
        );
        let ad_high = make_signed_ad_with_metrics(
            "High-Volume Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            high_metrics(),
        );

        registry.register(ad_low).unwrap();
        registry.register(ad_high).unwrap();

        let results = registry.query_by_action("schema:SearchAction");
        assert_eq!(results.len(), 2);
        // Must be insertion order, NOT ranked by metrics
        assert_eq!(results[0].name, "Low-Volume Agent");
        assert_eq!(results[1].name, "High-Volume Agent");
    }

    #[test]
    fn query_by_action_and_metrics_returns_tuples() {
        let mut registry = MarketplaceRegistry::new();

        let metrics = high_metrics();
        let ad_with = make_signed_ad_with_metrics(
            "Agent With Metrics",
            vec!["schema:SearchAction".into()],
            vec![],
            metrics.clone(),
        );
        let ad_without = make_signed_ad(
            "Agent Without Metrics",
            vec!["schema:SearchAction".into()],
            vec![],
        );

        registry.register(ad_with).unwrap();
        registry.register(ad_without).unwrap();

        let results = registry.query_by_action_and_metrics("schema:SearchAction");
        assert_eq!(results.len(), 2);

        // First result has metrics
        assert_eq!(results[0].0.name, "Agent With Metrics");
        assert_eq!(results[0].1, Some(&metrics));

        // Second result has no metrics
        assert_eq!(results[1].0.name, "Agent Without Metrics");
        assert_eq!(results[1].1, None);
    }

    #[test]
    fn query_by_action_and_metrics_preserves_insertion_order() {
        let mut registry = MarketplaceRegistry::new();

        // Insert in specific order with varying metrics
        let names = ["Alpha", "Beta", "Gamma", "Delta"];
        for name in &names {
            let ad = make_signed_ad_with_metrics(
                name,
                vec!["schema:SearchAction".into()],
                vec![],
                OperatorMetrics {
                    total_receipts: rand::random::<u64>() % 10000,
                    bilateral_attestations: rand::random::<u64>() % 10000,
                    unique_counterparties: rand::random::<u64>() % 1000,
                    action_types: vec!["schema:SearchAction".into()],
                    tee_sessions_pct: rand::random::<f64>(),
                    first_seen: None,
                    uptime_days: rand::random::<u64>() % 365,
                },
            );
            registry.register(ad).unwrap();
        }

        let results = registry.query_by_action_and_metrics("schema:SearchAction");
        assert_eq!(results.len(), 4);

        // Verify insertion order is preserved regardless of random metrics
        for (i, name) in names.iter().enumerate() {
            assert_eq!(results[i].0.name, *name);
        }
    }

    #[test]
    fn query_by_action_and_metrics_filters_by_action_only() {
        let mut registry = MarketplaceRegistry::new();

        let search_ad = make_signed_ad_with_metrics(
            "Search Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            high_metrics(),
        );
        let pay_ad = make_signed_ad_with_metrics(
            "Pay Agent",
            vec!["schema:PayAction".into()],
            vec![],
            low_metrics(),
        );

        registry.register(search_ad).unwrap();
        registry.register(pay_ad).unwrap();

        let results = registry.query_by_action_and_metrics("schema:SearchAction");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.name, "Search Agent");

        let results = registry.query_by_action_and_metrics("schema:PayAction");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.name, "Pay Agent");

        let results = registry.query_by_action_and_metrics("schema:NoSuchAction");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn query_with_metrics_filters_by_disclosure() {
        let mut registry = MarketplaceRegistry::new();

        let open_ad = make_signed_ad_with_metrics(
            "Open Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            low_metrics(),
        );
        let restricted_ad = make_signed_ad_with_metrics(
            "Restricted Agent",
            vec!["schema:SearchAction".into()],
            vec!["schema:Person.name".into()],
            high_metrics(),
        );

        registry.register(open_ad).unwrap();
        registry.register(restricted_ad).unwrap();

        // No properties available: only open agent matches
        let results = registry.query_with_metrics("schema:SearchAction", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Open Agent");

        // With required property: both match
        let results = registry.query_with_metrics("schema:SearchAction", &["schema:Person.name"]);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_with_metrics_preserves_insertion_order() {
        let mut registry = MarketplaceRegistry::new();

        // Insert high-metrics agent first, low-metrics second
        let ad_high = make_signed_ad_with_metrics(
            "High-Volume Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            high_metrics(),
        );
        let ad_low = make_signed_ad_with_metrics(
            "Low-Volume Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            low_metrics(),
        );

        registry.register(ad_high).unwrap();
        registry.register(ad_low).unwrap();

        let results = registry.query_with_metrics("schema:SearchAction", &[]);
        assert_eq!(results.len(), 2);
        // Must be insertion order
        assert_eq!(results[0].name, "High-Volume Agent");
        assert_eq!(results[1].name, "Low-Volume Agent");
    }

    #[test]
    fn query_with_metrics_returns_ads_with_metrics_attached() {
        let mut registry = MarketplaceRegistry::new();

        let metrics = high_metrics();
        let ad = make_signed_ad_with_metrics(
            "Metricated Agent",
            vec!["schema:SearchAction".into()],
            vec![],
            metrics.clone(),
        );

        registry.register(ad).unwrap();

        let results = registry.query_with_metrics("schema:SearchAction", &[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metrics.as_ref(), Some(&metrics));
    }

    #[test]
    fn metrics_do_not_affect_registration() {
        // Ads with and without metrics should both register successfully
        let mut registry = MarketplaceRegistry::new();

        let ad_no_metrics =
            make_signed_ad("No Metrics", vec!["schema:SearchAction".into()], vec![]);
        let ad_with_metrics = make_signed_ad_with_metrics(
            "With Metrics",
            vec!["schema:SearchAction".into()],
            vec![],
            low_metrics(),
        );

        assert!(registry.register(ad_no_metrics).is_ok());
        assert!(registry.register(ad_with_metrics).is_ok());
        assert_eq!(registry.len(), 2);
    }
}
