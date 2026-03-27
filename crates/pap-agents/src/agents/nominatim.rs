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
            .user_agent("Papillon/0.1 (PAP Browser; mailto:pap@baur-software.com)")
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

#[cfg(test)]
mod tests {
    use super::*;

    // Real-format Nominatim JSON response for "Paris"
    const REAL_PAYLOAD: &str = r#"[{
        "place_id": 308196556,
        "licence": "Data © OpenStreetMap contributors, ODbL 1.0.",
        "osm_type": "relation",
        "osm_id": 7444,
        "lat": "48.8588897",
        "lon": "2.3200410217200766",
        "class": "boundary",
        "type": "administrative",
        "place_rank": 15,
        "importance": 0.8042945684944932,
        "addresstype": "city",
        "name": "Paris",
        "display_name": "Paris, Île-de-France, Metropolitan France, France",
        "boundingbox": ["48.8155755", "48.9021560", "2.2241220", "2.4697602"]
    }]"#;

    #[test]
    fn deserialize_real_payload() {
        let results: Vec<NominatimResult> = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(results.len(), 1);

        let r = &results[0];
        assert_eq!(
            r.display_name,
            "Paris, Île-de-France, Metropolitan France, France"
        );
        assert_eq!(r.lat, "48.8588897");
        assert_eq!(r.lon, "2.3200410217200766");
        assert_eq!(r.place_type, "administrative");
    }

    #[test]
    fn lat_lon_parse_as_f64() {
        let results: Vec<NominatimResult> = serde_json::from_str(REAL_PAYLOAD).unwrap();
        let r = &results[0];
        let lat: f64 = r.lat.parse().unwrap();
        let lon: f64 = r.lon.parse().unwrap();
        assert!((lat - 48.859).abs() < 0.01);
        assert!((lon - 2.320).abs() < 0.01);
    }
}
