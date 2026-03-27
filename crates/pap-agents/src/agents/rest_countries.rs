use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Percent-encode a string for use in URL paths.
fn url_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from(b as char)
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

/// REST Countries — zero disclosure, public API for country data.
pub struct RestCountriesExecutor;

impl AgentExecutor for RestCountriesExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "REST Countries",
            provider: "restcountries.com",
            action: "schema:SearchAction",
            object_types: &["schema:Country"],
            requires_disclosure: &[],
            returns: &["schema:Country"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillon/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: Vec<RestCountry> = client
            .get(format!(
                "https://restcountries.com/v3.1/name/{}",
                url_encode(query)
            ))
            .query(&[(
                "fields",
                "name,capital,region,subregion,population,flags,languages,currencies",
            )])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("REST Countries request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("REST Countries parse: {e}"))
            })?;

        let countries: Vec<serde_json::Value> = resp
            .into_iter()
            .take(5)
            .map(|c| {
                let capital = c.capital.unwrap_or_default().join(", ");
                let languages: Vec<String> =
                    c.languages.unwrap_or_default().into_values().collect();

                json!({
                    "@type": "Country",
                    "name": c.name.common,
                    "alternateName": c.name.official,
                    "containedInPlace": {
                        "@type": "Place",
                        "name": c.region
                    },
                    "description": format!(
                        "Region: {}{}. Capital: {}. Population: {}. Languages: {}",
                        c.region,
                        c.subregion.map(|s| format!(" / {s}")).unwrap_or_default(),
                        capital,
                        c.population,
                        languages.join(", ")
                    ),
                    "population": c.population,
                    "image": c.flags.and_then(|f| f.png)
                })
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "SearchResultsPage",
            "query": query,
            "mainEntity": {
                "@type": "ItemList",
                "numberOfItems": countries.len(),
                "itemListElement": countries
            }
        }))
    }
}

#[derive(Deserialize)]
struct RestCountry {
    name: CountryName,
    capital: Option<Vec<String>>,
    region: String,
    subregion: Option<String>,
    population: u64,
    flags: Option<CountryFlags>,
    languages: Option<std::collections::HashMap<String, String>>,
    #[allow(dead_code)]
    currencies: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct CountryName {
    common: String,
    official: String,
}

#[derive(Deserialize)]
struct CountryFlags {
    png: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_PAYLOAD: &str = r#"[{
        "flags": {
            "png": "https://flagcdn.com/w320/fr.png",
            "svg": "https://flagcdn.com/fr.svg",
            "alt": "The flag of France is composed of three equal vertical bands of blue, white and red."
        },
        "name": {
            "common": "France",
            "official": "French Republic",
            "nativeName": { "fra": { "official": "République française", "common": "France" } }
        },
        "currencies": { "EUR": { "name": "euro", "symbol": "€" } },
        "languages": { "fra": "French" },
        "capital": ["Paris"],
        "region": "Europe",
        "subregion": "Western Europe",
        "population": 66351959
    }]"#;

    #[test]
    fn deserialize_real_payload() {
        let countries: Vec<RestCountry> = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(countries.len(), 1);

        let c = &countries[0];
        assert_eq!(c.name.common, "France");
        assert_eq!(c.name.official, "French Republic");
        assert_eq!(c.capital.as_ref().unwrap(), &["Paris"]);
        assert_eq!(c.region, "Europe");
        assert_eq!(c.subregion.as_deref(), Some("Western Europe"));
        assert_eq!(c.population, 66351959);
        assert_eq!(
            c.flags.as_ref().unwrap().png.as_deref(),
            Some("https://flagcdn.com/w320/fr.png")
        );
        assert_eq!(c.languages.as_ref().unwrap().get("fra").unwrap(), "French");
    }

    #[test]
    fn deserialize_minimal_country() {
        // API may return entries with missing optional fields
        let json = r#"[{
            "name": { "common": "Atlantis", "official": "Republic of Atlantis" },
            "region": "Unknown",
            "population": 0
        }]"#;
        let countries: Vec<RestCountry> = serde_json::from_str(json).unwrap();
        assert_eq!(countries[0].name.common, "Atlantis");
        assert!(countries[0].capital.is_none());
        assert!(countries[0].flags.is_none());
        assert!(countries[0].languages.is_none());
    }

    #[test]
    fn url_encode_spaces_and_special() {
        assert_eq!(url_encode("New Zealand"), "New%20Zealand");
        assert_eq!(url_encode("Côte d'Ivoire"), "C%C3%B4te%20d%27Ivoire");
    }
}
