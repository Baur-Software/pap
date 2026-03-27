use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Nominatim geocoding — zero disclosure, public API.
/// Rate-limited to 1 req/s by Nominatim policy.
pub struct NominatimExecutor;

impl AgentExecutor for NominatimExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Nominatim Geocoding",
            provider: "OpenStreetMap Foundation",
            action: "schema:FindAction",
            object_types: &["schema:Place"],
            requires_disclosure: &[],
            returns: &["schema:Place"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser; mailto:pap@baur-software.com)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let results: Vec<NominatimResult> = client
            .get("https://nominatim.openstreetmap.org/search")
            .query(&[("q", query), ("format", "json"), ("limit", "5")])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Nominatim request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Nominatim parse: {e}"))
            })?;

        let places: Vec<serde_json::Value> = results
            .into_iter()
            .filter_map(|r| {
                let lat: f64 = r.lat.parse().ok()?;
                let lon: f64 = r.lon.parse().ok()?;
                Some(json!({
                    "@type": "Place",
                    "name": r.display_name,
                    "geo": {
                        "@type": "GeoCoordinates",
                        "latitude": lat,
                        "longitude": lon
                    },
                    "additionalType": r.place_type
                }))
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "ItemList",
            "query": query,
            "numberOfItems": places.len(),
            "itemListElement": places
        }))
    }
}

#[derive(Deserialize)]
struct NominatimResult {
    display_name: String,
    lat: String,
    lon: String,
    #[serde(rename = "type")]
    place_type: String,
}
