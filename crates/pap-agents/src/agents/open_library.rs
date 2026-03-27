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
            .user_agent("Papillon/0.1 (PAP Browser)")
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

#[cfg(test)]
mod tests {
    use super::*;

    // Real payload from https://openlibrary.org/search.json?q=rust+programming&limit=1
    const REAL_PAYLOAD: &str = r#"{
        "numFound": 42,
        "start": 0,
        "numFoundExact": true,
        "docs": [{
            "author_key": ["OL7467124A", "OL7467125A"],
            "author_name": ["Steve Klabnik", "Carol Nichols"],
            "cover_edition_key": "OL26740375M",
            "cover_i": 8508621,
            "ebook_access": "no_ebook",
            "edition_count": 4,
            "first_publish_year": 2018,
            "has_fulltext": false,
            "key": "/works/OL19080231W",
            "language": ["eng"],
            "public_scan_b": false,
            "title": "The Rust Programming Language"
        }]
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: OpenLibraryResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(resp.docs.len(), 1);

        let doc = &resp.docs[0];
        assert_eq!(doc.title, "The Rust Programming Language");
        assert_eq!(doc.key, "/works/OL19080231W");
        assert_eq!(doc.first_publish_year, Some(2018));
        assert_eq!(
            doc.author_name.as_ref().unwrap(),
            &["Steve Klabnik", "Carol Nichols"]
        );
        // isbn and number_of_pages_median not in this response — confirms Option works
        assert!(doc.isbn.is_none());
        assert!(doc.number_of_pages_median.is_none());
    }

    #[test]
    fn deserialize_with_isbn() {
        let json = r#"{
            "docs": [{
                "title": "Programming Rust",
                "key": "/works/OL123",
                "isbn": ["978-1-4919-2728-1"],
                "number_of_pages_median": 622
            }]
        }"#;
        let resp: OpenLibraryResponse = serde_json::from_str(json).unwrap();
        let doc = &resp.docs[0];
        assert_eq!(doc.isbn.as_ref().unwrap()[0], "978-1-4919-2728-1");
        assert_eq!(doc.number_of_pages_median, Some(622));
    }
}
