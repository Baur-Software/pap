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
            .user_agent("Papillion/0.1 (PAP Browser)")
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
