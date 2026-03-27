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
            .user_agent("Papillon/0.1 (PAP Browser; mailto:pap@baur-software.com)")
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

#[cfg(test)]
mod tests {
    use super::*;

    // Real-format Wikipedia REST API v1 search response
    const REAL_PAYLOAD: &str = r#"{
        "pages": [{
            "id": 73786932,
            "key": "Rust_(programming_language)",
            "title": "Rust (programming language)",
            "excerpt": "<span class=\"searchmatch\">Rust</span> is a general-purpose programming language emphasizing performance, type safety, and concurrency.",
            "description": "Programming language",
            "thumbnail": {
                "mimetype": "image/png",
                "width": 50,
                "height": 50,
                "url": "//upload.wikimedia.org/wikipedia/commons/thumb/d/d5/Rust_programming_language_black_logo.svg/50px-Rust_programming_language_black_logo.svg.png"
            }
        }]
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: WikiSearchResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(resp.pages.len(), 1);

        let page = &resp.pages[0];
        assert_eq!(page.title, "Rust (programming language)");
        assert_eq!(page.key, "Rust_(programming_language)");
        assert!(page.excerpt.as_ref().unwrap().contains("searchmatch"));
        assert_eq!(page.description.as_deref(), Some("Programming language"));
    }

    #[test]
    fn searchmatch_spans_stripped() {
        let resp: WikiSearchResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        let page = resp.pages.into_iter().next().unwrap();
        let snippet = page
            .excerpt
            .unwrap_or_default()
            .replace("<span class=\"searchmatch\">", "")
            .replace("</span>", "");
        assert!(!snippet.contains("searchmatch"));
        assert!(snippet.contains("Rust"));
    }

    #[test]
    fn deserialize_missing_optional_fields() {
        let json = r#"{
            "pages": [{
                "id": 1,
                "key": "Test",
                "title": "Test Page"
            }]
        }"#;
        let resp: WikiSearchResponse = serde_json::from_str(json).unwrap();
        assert!(resp.pages[0].excerpt.is_none());
        assert!(resp.pages[0].description.is_none());
    }
}
