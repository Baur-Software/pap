use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// Nominatim geocoding agent.
///
/// Calls the OpenStreetMap Nominatim API — zero disclosure, public API.
/// Uses FindAction (not SearchAction), demonstrating action type diversity
/// in the federated registry. Rate-limited to 1 req/s by Nominatim policy.
/// Sessions are TTL-bounded and reaped automatically.
pub struct NominatimAgent {
    sessions: SessionStore<Option<String>>, // query
}

impl Default for NominatimAgent {
    fn default() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl NominatimAgent {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AgentHandler for NominatimAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:FindAction" {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}",
                token.action
            )));
        }

        let session_id = uuid::Uuid::new_v4().to_string();
        let did = self.sessions.insert(session_id.clone(), None);
        Ok((session_id, did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        if !self.sessions.exists(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        let query = disclosures
            .iter()
            .find_map(|d| d.get("query").and_then(|v| v.as_str()))
            .map(String::from);

        if let Some(q) = query {
            self.sessions.with_mut(session_id, |data| {
                *data = Some(q);
            })?;
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let query = self
            .sessions
            .with(session_id, |data| data.clone())?
            .ok_or_else(|| {
                TransportError::ServerError("No query provided in disclosures".into())
            })?;

        // Nominatim requires a descriptive User-Agent per usage policy
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser; mailto:pap@baur-software.com)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let results: Vec<NominatimResult> = client
            .get("https://nominatim.openstreetmap.org/search")
            .query(&[("q", query.as_str()), ("format", "json"), ("limit", "5")])
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

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        let key = self.sessions.signing_key(&receipt.session_id);
        match key {
            Some(k) => receipt.co_sign(&k),
            None => {
                let k = SessionKeypair::generate();
                receipt.co_sign(k.signing_key());
            }
        }
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.remove(session_id);
        Ok(())
    }
}

// ── Nominatim API types ───────────────────────────────────────

#[derive(Deserialize)]
struct NominatimResult {
    display_name: String,
    lat: String,
    lon: String,
    #[serde(rename = "type")]
    place_type: String,
}
