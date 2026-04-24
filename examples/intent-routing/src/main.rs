#![allow(clippy::unwrap_used)]
//! Intent-routing example demonstrating Papillon's intent pipeline:
//!
//! Level 1 — URL fast-path  (`papillon_shared::intent::detect_intent`)
//! Level 2 — BM25 semantic index (`pap_agents::IntentIndex::classify`)
//! Fallback — DuckDuckGo web search when BM25 confidence is below threshold.
//!            In production Papillon fires a live PAP handshake with a
//!            discovered `schema:AnalyzeAction` federation agent here.
//!            See `apps/papillon/src/commands/canvas/intent.rs`.

use chrono::{Duration, Utc};
use pap_agents::{DynamicAgentDef, DynamicAgentSource, HttpEndpointConfig, HttpMethod};
use pap_core::mandate::{Mandate, MandateChain};
use pap_core::receipt::TransactionReceipt;
use pap_core::scope::{DisclosureSet, Scope, ScopeAction};
use pap_core::session::{CapabilityToken, Session};
use pap_did::{DidDocument, PrincipalKeypair, SessionKeypair};
use pap_marketplace::{AgentAdvertisement, MarketplaceRegistry};

fn main() {}

// ── Catalog ───────────────────────────────────────────────────────────────────

/// Build a representative 7-agent catalog for the intent-routing demo.
/// Covers CheckAction (weather), SearchAction (web, handmade goods, academic),
/// FindAction (geocode), ReserveAction (hotel), and AskAction (on-device AI).
fn build_catalog() -> Vec<DynamicAgentDef> {
    vec![
        agent(
            "Open-Meteo Weather",
            "Open-Meteo",
            "Real-time weather forecast and temperature data for any location worldwide.",
            "schema:CheckAction",
            &["schema:Place"],
            &["schema:WeatherForecast"],
            "You are a weather assistant. Provide current conditions, temperature, \
             humidity, wind speed, and forecast. User asks for weather, temperature, \
             climate, forecast.",
        ),
        agent(
            "Etsy Shop Search",
            "Etsy",
            "Search handmade, vintage, and craft items on Etsy marketplace.",
            "schema:SearchAction",
            &["schema:Product"],
            &["schema:Product"],
            "You are a handmade goods discovery assistant. Describe Etsy listings: \
             product name, maker, materials, price. Users search for handmade candles, \
             jewelry, art, crafts.",
        ),
        agent(
            "DuckDuckGo Search",
            "DuckDuckGo",
            "General web search with zero tracking.",
            "schema:SearchAction",
            &["schema:WebPage"],
            &["schema:SearchResult"],
            "You are a privacy-first web search assistant. Return relevant results \
             for any query. General search, web lookup, find information.",
        ),
        agent(
            "arXiv Papers",
            "arXiv",
            "Search academic research papers in physics, maths, and computer science.",
            "schema:SearchAction",
            &["schema:ScholarlyArticle"],
            &["schema:ScholarlyArticle"],
            "You are a research paper discovery assistant. Find scientific papers, \
             academic articles, and research on any scholarly topic.",
        ),
        agent(
            "Nominatim Geocoding",
            "OpenStreetMap",
            "Geocode addresses and find coordinates for locations.",
            "schema:FindAction",
            &["schema:Place"],
            &["schema:GeoCoordinates"],
            "You are a geocoding assistant. Convert addresses to coordinates. \
             Find latitude longitude for any location or address.",
        ),
        agent(
            "Hotel Booking Lookup",
            "Hotels.com",
            "Search and reserve hotel rooms for any destination and date range.",
            "schema:ReserveAction",
            &["schema:LodgingBusiness"],
            &["schema:LodgingReservation"],
            "You are a hotel booking assistant. Help users find and book hotel rooms. \
             Users ask to book, reserve, find hotel, lodging in a city.",
        ),
        agent(
            "On-Device AI",
            "Papillon",
            "Local language model for open-ended questions and synthesis.",
            "schema:AskAction",
            &["schema:Question"],
            &["schema:Answer"],
            "You are a local AI assistant. Answer open-ended questions, explain \
             concepts, summarise content, and help with any task requiring language \
             understanding.",
        ),
    ]
}

fn agent(
    name: &str,
    provider: &str,
    description: &str,
    action: &str,
    object_types: &[&str],
    returns: &[&str],
    llm_instructions: &str,
) -> DynamicAgentDef {
    DynamicAgentDef {
        agent_did: None,
        schema_version: 1,
        version: "0.1.0".into(),
        name: name.into(),
        provider: provider.into(),
        description: description.into(),
        action: action.into(),
        object_types: object_types.iter().map(|s| s.to_string()).collect(),
        requires_disclosure: vec![],
        returns: returns.iter().map(|s| s.to_string()).collect(),
        endpoint: Some(HttpEndpointConfig {
            url_template: format!(
                "https://example.com/api/{}",
                name.to_lowercase().replace(' ', "-")
            ),
            method: HttpMethod::Get,
            headers: Default::default(),
            body_template: None,
            response_jsonpath: "$".into(),
            response_schema_type: returns.first().copied().unwrap_or("schema:Thing").into(),
            response_mapping: Default::default(),
            timeout_secs: 5,
        }),
        llm_instructions: llm_instructions.into(),
        subagents: vec![],
        source: DynamicAgentSource::Catalog,
        operator_key_seed: None,
        published_to: vec![],
        catalog_path: None,
        configurable_properties: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
        updated_at: "2026-01-01T00:00:00Z".into(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm25_weather_routes_to_check_action() {
        let catalog = build_catalog();
        let idx = pap_agents::IntentIndex::new(&catalog);
        let m = idx.classify("weather in Tokyo", 0.25).expect("should match");
        assert_eq!(m.action, "schema:CheckAction");
        assert_eq!(m.agent_name.as_deref(), Some("Open-Meteo Weather"));
    }

    #[test]
    fn bm25_handmade_candles_routes_to_etsy() {
        let catalog = build_catalog();
        let idx = pap_agents::IntentIndex::new(&catalog);
        let m = idx
            .classify("find handmade candles", 0.25)
            .expect("should match");
        assert_eq!(m.action, "schema:SearchAction");
        assert_eq!(m.agent_name.as_deref(), Some("Etsy Shop Search"));
    }

    #[test]
    fn url_fast_path_returns_read_action() {
        let (action, agent, _) =
            papillon_shared::intent::detect_intent("https://example.com");
        assert_eq!(action, "schema:ReadAction");
        assert_eq!(agent, "Web Page Reader");
    }

    #[test]
    fn open_ended_falls_through_bm25_to_fallback() {
        let catalog = build_catalog();
        // "explain quantum entanglement" has no confident catalog match.
        // BM25 returns None → fallback to DuckDuckGo.
        // In production this is where a live schema:AnalyzeAction handshake fires.
        let idx = pap_agents::IntentIndex::new(&catalog);
        let result = idx.classify("explain quantum entanglement", 0.25);
        assert!(result.is_none(), "open-ended query must fall through BM25");
    }
}
