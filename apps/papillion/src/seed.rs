use std::collections::HashMap;

use pap_did::PrincipalKeypair;
use pap_federation::FederatedRegistry;
use pap_marketplace::AgentAdvertisement;

/// Seed the initial federated registry with agents backed by real services.
///
/// Every agent here wraps an actual API or on-device capability. No fake
/// companies, no placeholder agents, no demo data.
///
/// Returns the registry and agent keypairs (retained for handshake co-signing).
pub fn seed_registry() -> (FederatedRegistry, HashMap<String, PrincipalKeypair>) {
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
            .expect("registry seed registration should not fail");
        keypairs.insert(name.to_string(), kp);
    };

    // DuckDuckGo Web Search — real API, zero disclosure
    // Backed by DuckDuckGo Instant Answer JSON API (no tracking, no login).
    register(
        "DuckDuckGo Search",
        "DuckDuckGo",
        vec!["schema:SearchAction".into()],
        vec!["schema:WebPage".into()],
        vec![],
        vec!["schema:SearchResult".into()],
        &mut keypairs,
    );

    // Wikipedia Knowledge — real API, zero disclosure
    // Backed by Wikimedia REST API (public, no auth required).
    register(
        "Wikipedia Knowledge",
        "Wikimedia Foundation",
        vec!["schema:SearchAction".into()],
        vec!["schema:Article".into()],
        vec![],
        vec!["schema:Article".into()],
        &mut keypairs,
    );

    // On-Device AI (Mistral) — real inference, zero disclosure
    // Backed by Candle + Mistral 7B GGUF running entirely on-device.
    register(
        "On-Device AI",
        "Papillion",
        vec!["schema:AskAction".into()],
        vec!["schema:Question".into()],
        vec![],
        vec!["schema:Answer".into()],
        &mut keypairs,
    );

    // Open-Meteo Weather — real API, REQUIRES GeoCoordinates disclosure
    // Backed by Open-Meteo free weather API (no auth required).
    register(
        "Open-Meteo Weather",
        "Open-Meteo",
        vec!["schema:CheckAction".into()],
        vec!["schema:WeatherForecast".into()],
        vec!["schema:GeoCoordinates".into()],
        vec!["schema:WeatherForecast".into()],
        &mut keypairs,
    );

    // Open Library Books — real API, zero disclosure
    // Backed by Open Library Search API (public, no auth required).
    register(
        "Open Library Books",
        "Internet Archive",
        vec!["schema:SearchAction".into()],
        vec!["schema:Book".into()],
        vec![],
        vec!["schema:Book".into()],
        &mut keypairs,
    );

    // Nominatim Geocoding — real API, zero disclosure
    // Backed by OpenStreetMap Nominatim API (public, requires User-Agent).
    register(
        "Nominatim Geocoding",
        "OpenStreetMap Foundation",
        vec!["schema:FindAction".into()],
        vec!["schema:Place".into()],
        vec![],
        vec!["schema:Place".into()],
        &mut keypairs,
    );

    // Frankfurter Currency Exchange — real API, zero disclosure
    // Backed by Frankfurter API with ECB reference rates (public, no auth).
    register(
        "Frankfurter Exchange",
        "Frankfurter",
        vec!["schema:TradeAction".into()],
        vec!["schema:MonetaryAmount".into()],
        vec![],
        vec!["schema:MonetaryAmount".into()],
        &mut keypairs,
    );

    // Hacker News Search — real API, zero disclosure
    // Backed by HN Algolia search API (public, no auth required).
    register(
        "Hacker News",
        "Y Combinator",
        vec!["schema:SearchAction".into()],
        vec!["schema:NewsArticle".into()],
        vec![],
        vec!["schema:NewsArticle".into()],
        &mut keypairs,
    );

    (registry, keypairs)
}
