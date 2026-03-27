use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// IP Geolocation — requires `schema:IPAddress` disclosure.
///
/// Demonstrates selective disclosure: the user must explicitly reveal an IP
/// address. The agent returns location data without storing the IP.
pub struct IpGeolocationExecutor;

impl AgentExecutor for IpGeolocationExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "IP Geolocation",
            provider: "ip-api.com",
            action: "schema:FindAction",
            object_types: &["schema:Place"],
            requires_disclosure: &["schema:IPAddress"],
            returns: &["schema:Place", "schema:GeoCoordinates"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let ip = query.trim();

        // Basic validation — must look like an IP address
        if !ip.contains('.') && !ip.contains(':') {
            return Err(TransportError::ServerError(
                "Expected an IP address (IPv4 or IPv6)".into(),
            ));
        }

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: IpApiResponse = client
            .get(format!("http://ip-api.com/json/{ip}"))
            .query(&[(
                "fields",
                "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as",
            )])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("IP Geolocation request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("IP Geolocation parse: {e}"))
            })?;

        if resp.status != "success" {
            return Err(TransportError::ServerError(
                resp.message.unwrap_or_else(|| "IP lookup failed".into()),
            ));
        }

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "Place",
            "name": format!(
                "{}, {}, {}",
                resp.city.as_deref().unwrap_or("Unknown"),
                resp.region_name.as_deref().unwrap_or(""),
                resp.country.as_deref().unwrap_or("")
            ),
            "address": {
                "@type": "PostalAddress",
                "addressCountry": resp.country,
                "addressRegion": resp.region_name,
                "addressLocality": resp.city,
                "postalCode": resp.zip
            },
            "geo": {
                "@type": "GeoCoordinates",
                "latitude": resp.lat,
                "longitude": resp.lon
            },
            "description": format!(
                "ISP: {}. Org: {}. Timezone: {}",
                resp.isp.as_deref().unwrap_or("—"),
                resp.org.as_deref().unwrap_or("—"),
                resp.timezone.as_deref().unwrap_or("—")
            )
        }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpApiResponse {
    status: String,
    message: Option<String>,
    country: Option<String>,
    region_name: Option<String>,
    city: Option<String>,
    zip: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    timezone: Option<String>,
    isp: Option<String>,
    org: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "as")]
    as_info: Option<String>,
}
