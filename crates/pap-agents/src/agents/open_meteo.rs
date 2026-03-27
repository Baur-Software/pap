use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Open-Meteo weather forecast — REQUIRES GeoCoordinates disclosure.
pub struct OpenMeteoExecutor;

impl AgentExecutor for OpenMeteoExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Open-Meteo Weather",
            provider: "Open-Meteo",
            action: "schema:CheckAction",
            object_types: &["schema:WeatherForecast"],
            requires_disclosure: &["schema:GeoCoordinates"],
            returns: &["schema:WeatherForecast"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let (lat, lon) = parse_coordinates(query)?;

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: OpenMeteoResponse = client
            .get("https://api.open-meteo.com/v1/forecast")
            .query(&[
                ("latitude", lat.to_string()),
                ("longitude", lon.to_string()),
                (
                    "current".into(),
                    "temperature_2m,wind_speed_10m,weather_code".into(),
                ),
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
}

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
