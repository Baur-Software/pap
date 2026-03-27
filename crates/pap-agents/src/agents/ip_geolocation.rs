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

#[cfg(test)]
mod tests {
    use super::*;

    // Real payload from http://ip-api.com/json/8.8.8.8
    const REAL_PAYLOAD: &str = r#"{
        "status": "success",
        "country": "United States",
        "regionName": "Virginia",
        "city": "Ashburn",
        "zip": "20149",
        "lat": 39.03,
        "lon": -77.5,
        "timezone": "America/New_York",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "as": "AS15169 Google LLC"
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: IpApiResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(resp.status, "success");
        assert_eq!(resp.country.as_deref(), Some("United States"));
        assert_eq!(resp.region_name.as_deref(), Some("Virginia"));
        assert_eq!(resp.city.as_deref(), Some("Ashburn"));
        assert_eq!(resp.zip.as_deref(), Some("20149"));
        assert!((resp.lat.unwrap() - 39.03).abs() < 0.01);
        assert!((resp.lon.unwrap() - (-77.5)).abs() < 0.01);
        assert_eq!(resp.timezone.as_deref(), Some("America/New_York"));
        assert_eq!(resp.isp.as_deref(), Some("Google LLC"));
        assert_eq!(resp.org.as_deref(), Some("Google Public DNS"));
        assert_eq!(resp.as_info.as_deref(), Some("AS15169 Google LLC"));
    }

    #[test]
    fn deserialize_failure_response() {
        let json = r#"{
            "status": "fail",
            "message": "reserved range"
        }"#;
        let resp: IpApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.status, "fail");
        assert_eq!(resp.message.as_deref(), Some("reserved range"));
        assert!(resp.country.is_none());
        assert!(resp.lat.is_none());
    }

    #[test]
    fn rejects_non_ip_input() {
        let executor = IpGeolocationExecutor;
        let err = executor.execute("hello world").unwrap_err();
        assert!(format!("{err:?}").contains("Expected an IP address"));
    }
}
