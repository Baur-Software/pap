use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Open Library book search — zero disclosure, public API.
pub struct OpenLibraryExecutor;

impl AgentExecutor for OpenLibraryExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Open Library Books",
            provider: "Internet Archive",
            action: "schema:SearchAction",
            object_types: &["schema:Book"],
            requires_disclosure: &[],
            returns: &["schema:Book"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: OpenLibraryResponse = client
            .get("https://openlibrary.org/search.json")
            .query(&[("q", query), ("limit", "5")])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Open Library request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Open Library parse: {e}"))
            })?;

        let results: Vec<serde_json::Value> = resp
            .docs
            .into_iter()
            .map(|doc| {
                let mut book = json!({
                    "@type": "Book",
                    "name": doc.title,
                    "url": format!("https://openlibrary.org{}", doc.key),
                });

                if let Some(authors) = doc.author_name {
                    if let Some(first) = authors.first() {
                        book["author"] = json!({
                            "@type": "Person",
                            "name": first
                        });
                    }
                }
                if let Some(year) = doc.first_publish_year {
                    book["datePublished"] = json!(year.to_string());
                }
                if let Some(ref isbns) = doc.isbn {
                    if let Some(isbn) = isbns.first() {
                        book["isbn"] = json!(isbn);
                    }
                }
                if let Some(pages) = doc.number_of_pages_median {
                    book["numberOfPages"] = json!(pages);
                }

                book
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "ItemList",
            "query": query,
            "numberOfItems": results.len(),
            "itemListElement": results
        }))
    }
}

#[derive(Deserialize)]
struct OpenLibraryResponse {
    docs: Vec<OpenLibraryDoc>,
}

#[derive(Deserialize)]
struct OpenLibraryDoc {
    title: String,
    author_name: Option<Vec<String>>,
    first_publish_year: Option<i32>,
    key: String,
    isbn: Option<Vec<String>>,
    number_of_pages_median: Option<i32>,
}
