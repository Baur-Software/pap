use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Wikipedia knowledge search — zero disclosure, public API.
pub struct WikipediaExecutor;

impl AgentExecutor for WikipediaExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Wikipedia Knowledge",
            provider: "Wikimedia Foundation",
            action: "schema:SearchAction",
            object_types: &["schema:Article"],
            requires_disclosure: &[],
            returns: &["schema:Article"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser; mailto:pap@baur-software.com)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: WikiSearchResponse = client
            .get("https://en.wikipedia.org/w/rest.php/v1/search/page")
            .query(&[("q", query), ("limit", "5")])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Wikipedia request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Wikipedia parse: {e}"))
            })?;

        let results: Vec<serde_json::Value> = resp
            .pages
            .into_iter()
            .map(|p| {
                let snippet = p
                    .excerpt
                    .or(p.description)
                    .unwrap_or_default()
                    .replace("<span class=\"searchmatch\">", "")
                    .replace("</span>", "");
                json!({
                    "@type": "Article",
                    "name": p.title,
                    "url": format!("https://en.wikipedia.org/wiki/{}", p.key),
                    "description": snippet
                })
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "SearchResultsPage",
            "query": query,
            "mainEntity": {
                "@type": "ItemList",
                "numberOfItems": results.len(),
                "itemListElement": results
            }
        }))
    }
}

#[derive(Deserialize)]
struct WikiSearchResponse {
    pages: Vec<WikiPage>,
}

#[derive(Deserialize)]
struct WikiPage {
    title: String,
    excerpt: Option<String>,
    description: Option<String>,
    key: String,
}
