use std::collections::HashMap;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_marketplace::AgentAdvertisement;

/// Seed a FederatedRegistry with demo agents for the built-in `pap://demo` registry.
/// Returns the registry and the agent keypairs (retained for demo runner co-signing).
pub fn seed_demo_registry() -> (FederatedRegistry, HashMap<String, PrincipalKeypair>) {
    let mut registry = FederatedRegistry::new();
    let mut keypairs = HashMap::new();

    let mut register = |name: &str,
                        provider: &str,
                        capabilities: Vec<String>,
                        object_types: Vec<String>,
                        requires_disclosure: Vec<String>,
                        returns: Vec<String>,
                        keypairs: &mut HashMap<String, PrincipalKeypair>| {
        let kp = PrincipalKeypair::generate();
        let did = kp.did();
        let mut ad = AgentAdvertisement::new(
            name,
            provider,
            &did,
            capabilities,
            object_types,
            requires_disclosure,
            returns,
        );
        ad.sign(kp.signing_key());
        registry
            .register_local(ad)
            .expect("demo seed registration should not fail");
        keypairs.insert(name.to_string(), kp);
    };

    // Web Search Agent — zero disclosure
    register(
        "Web Search Agent",
        "SearchCorp",
        vec!["schema:SearchAction".into()],
        vec!["schema:WebPage".into()],
        vec![],
        vec!["schema:SearchResult".into()],
        &mut keypairs,
    );

    // Flight Booking Agent — requires name + nationality
    register(
        "Flight Booking Agent",
        "SkyBook Airlines",
        vec!["schema:ReserveAction".into()],
        vec!["schema:Flight".into()],
        vec![
            "schema:Person.name".into(),
            "schema:Person.nationality".into(),
        ],
        vec!["schema:Ticket".into()],
        &mut keypairs,
    );

    // Hotel Booking Agent — requires name only
    register(
        "Hotel Booking Agent",
        "StayWell Hotels",
        vec!["schema:ReserveAction".into()],
        vec!["schema:LodgingReservation".into()],
        vec!["schema:Person.name".into()],
        vec!["schema:Reservation".into()],
        &mut keypairs,
    );

    // Payment Agent — zero disclosure
    register(
        "Payment Agent",
        "PayCorp",
        vec!["schema:PayAction".into()],
        vec!["schema:Invoice".into()],
        vec![],
        vec!["schema:Invoice".into()],
        &mut keypairs,
    );

    // Local AI Assistant — zero disclosure
    register(
        "Local AI Assistant",
        "LocalAI",
        vec!["schema:AskAction".into()],
        vec!["schema:Question".into()],
        vec![],
        vec!["schema:Answer".into()],
        &mut keypairs,
    );

    (registry, keypairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_creates_five_agents() {
        let (registry, _) = seed_demo_registry();
        assert_eq!(registry.len(), 5);
    }

    #[test]
    fn seed_creates_matching_keypairs() {
        let (_, keypairs) = seed_demo_registry();
        assert_eq!(keypairs.len(), 5);
    }

    #[test]
    fn seed_agent_names_match_keypair_keys() {
        let (registry, keypairs) = seed_demo_registry();
        let expected_names = [
            "Web Search Agent",
            "Flight Booking Agent",
            "Hotel Booking Agent",
            "Payment Agent",
            "Local AI Assistant",
        ];
        for name in &expected_names {
            assert!(keypairs.contains_key(*name), "Missing keypair for {name}");
        }
        let ads = registry.all_advertisements();
        for name in &expected_names {
            assert!(
                ads.iter().any(|ad| ad.name == *name),
                "Missing advertisement for {name}"
            );
        }
    }

    #[test]
    fn seed_agents_have_valid_dids() {
        let (_, keypairs) = seed_demo_registry();
        for (name, kp) in &keypairs {
            let did = kp.did();
            assert!(
                did.starts_with("did:key:z"),
                "Agent '{name}' DID should start with did:key:z, got {did}"
            );
        }
    }

    #[test]
    fn seed_search_agent_is_zero_disclosure() {
        let (registry, _) = seed_demo_registry();
        let ads = registry.all_advertisements();
        let search = ads.iter().find(|a| a.name == "Web Search Agent").unwrap();
        assert!(search.requires_disclosure.is_empty());
    }

    #[test]
    fn seed_flight_agent_requires_disclosure() {
        let (registry, _) = seed_demo_registry();
        let ads = registry.all_advertisements();
        let flight = ads
            .iter()
            .find(|a| a.name == "Flight Booking Agent")
            .unwrap();
        assert_eq!(flight.requires_disclosure.len(), 2);
    }

    #[test]
    fn seed_agents_are_signed() {
        let (registry, _) = seed_demo_registry();
        let ads = registry.all_advertisements();
        for ad in ads {
            // Signed advertisements have a non-empty hash
            assert!(!ad.hash().is_empty(), "Ad for {} should be signed", ad.name);
        }
    }

    #[test]
    fn seed_agents_have_capabilities() {
        let (registry, _) = seed_demo_registry();
        let ads = registry.all_advertisements();
        for ad in ads {
            assert!(
                !ad.capability.is_empty(),
                "Agent {} should have at least one capability",
                ad.name
            );
            for cap in &ad.capability {
                assert!(
                    cap.starts_with("schema:"),
                    "Capability should be a schema.org action"
                );
            }
        }
    }

    #[test]
    fn seed_registry_can_query_search_action() {
        let (registry, _) = seed_demo_registry();
        let results = registry.query_local("schema:SearchAction");
        assert!(!results.is_empty());
        assert!(results.iter().any(|a| a.name == "Web Search Agent"));
    }

    #[test]
    fn seed_registry_can_query_reserve_action() {
        let (registry, _) = seed_demo_registry();
        let results = registry.query_local("schema:ReserveAction");
        assert_eq!(results.len(), 2, "flight + hotel agents");
    }
}
