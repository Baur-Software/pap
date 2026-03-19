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
