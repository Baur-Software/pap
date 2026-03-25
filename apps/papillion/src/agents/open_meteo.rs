use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// Open-Meteo weather forecast agent.
///
/// Calls the Open-Meteo API — REQUIRES disclosure of GeoCoordinates.
/// This is the first agent in Papillion that exercises disclosure filtering:
/// users must authorize location sharing for this agent to appear in queries.
/// Coordinates arrive as "lat,lon" via `handle_disclosure`.
/// Sessions are TTL-bounded and reaped automatically.
pub struct OpenMeteoAgent {
    sessions: SessionStore<Option<String>>, // query containing lat,lon
}

impl Default for OpenMeteoAgent {
    fn default() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl OpenMeteoAgent {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AgentHandler for OpenMeteoAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:CheckAction" {
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
                TransportError::ServerError("No coordinates provided in disclosures".into())
            })?;

        let (lat, lon) = parse_coordinates(&query)?;

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: OpenMeteoResponse = client
            .get("https://api.open-meteo.com/v1/forecast")
            .query(&[
                ("latitude", lat.to_string()),
                ("longitude", lon.to_string()),
                ("current", "temperature_2m,wind_speed_10m,weather_code".into()),
            ])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Open-Meteo request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Open-Meteo parse: {e}"))
            })?;

        let condition = weather_code_description(resp.current.weather_code);

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "WeatherForecast",
            "geo": {
                "@type": "GeoCoordinates",
                "latitude": resp.latitude,
                "longitude": resp.longitude
            },
            "temperature": {
                "@type": "QuantitativeValue",
                "value": resp.current.temperature_2m,
                "unitCode": "CEL"
            },
            "windSpeed": {
                "@type": "QuantitativeValue",
                "value": resp.current.wind_speed_10m,
                "unitCode": "KMH"
            },
            "weatherCondition": condition,
            "weatherCode": resp.current.weather_code
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

// ── Open-Meteo API types ──────────────────────────────────────

#[derive(Deserialize)]
struct OpenMeteoResponse {
    latitude: f64,
    longitude: f64,
    current: CurrentWeather,
}

#[derive(Deserialize)]
struct CurrentWeather {
    temperature_2m: f64,
    wind_speed_10m: f64,
    weather_code: i32,
}

// ── Helpers ───────────────────────────────────────────────────

fn parse_coordinates(query: &str) -> Result<(f64, f64), TransportError> {
    let parts: Vec<&str> = query
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() >= 2 {
        if let (Ok(lat), Ok(lon)) = (parts[0].parse::<f64>(), parts[1].parse::<f64>()) {
            if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) {
                return Ok((lat, lon));
            }
        }
    }
    Err(TransportError::ServerError(
        "Expected coordinates as 'latitude,longitude' (e.g., '48.85,2.35')".into(),
    ))
}

/// Map WMO weather interpretation codes to human-readable descriptions.
fn weather_code_description(code: i32) -> &'static str {
    match code {
        0 => "Clear sky",
        1 => "Mainly clear",
        2 => "Partly cloudy",
        3 => "Overcast",
        45 => "Fog",
        48 => "Depositing rime fog",
        51 => "Light drizzle",
        53 => "Moderate drizzle",
        55 => "Dense drizzle",
        56 => "Light freezing drizzle",
        57 => "Dense freezing drizzle",
        61 => "Slight rain",
        63 => "Moderate rain",
        65 => "Heavy rain",
        66 => "Light freezing rain",
        67 => "Heavy freezing rain",
        71 => "Slight snowfall",
        73 => "Moderate snowfall",
        75 => "Heavy snowfall",
        77 => "Snow grains",
        80 => "Slight rain showers",
        81 => "Moderate rain showers",
        82 => "Violent rain showers",
        85 => "Slight snow showers",
        86 => "Heavy snow showers",
        95 => "Thunderstorm",
        96 => "Thunderstorm with slight hail",
        99 => "Thunderstorm with heavy hail",
        _ => "Unknown",
    }
}
