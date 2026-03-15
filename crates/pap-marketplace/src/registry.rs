use crate::advertisement::AgentAdvertisement;
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
    pub fn query_by_action(&self, action: &str) -> Vec<&AgentAdvertisement> {
        self.advertisements
            .iter()
            .filter(|ad| ad.supports_action(action))
            .collect()
    }

    /// Query for agents that support a given action AND whose disclosure
    /// requirements can be satisfied by the available properties.
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
}
