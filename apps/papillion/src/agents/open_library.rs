use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// Open Library book search agent.
///
/// Calls the Open Library Search API — zero disclosure, public API.
/// Same action type (SearchAction) as DuckDuckGo/Wikipedia but searches
/// books (schema:Book), demonstrating marketplace differentiation by object type.
/// Sessions are TTL-bounded and reaped automatically.
pub struct OpenLibraryAgent {
    sessions: SessionStore<Option<String>>, // query
}

impl Default for OpenLibraryAgent {
    fn default() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl OpenLibraryAgent {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AgentHandler for OpenLibraryAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:SearchAction" {
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
                TransportError::ServerError("No query provided in disclosures".into())
            })?;

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: OpenLibraryResponse = client
            .get("https://openlibrary.org/search.json")
            .query(&[("q", query.as_str()), ("limit", "5")])
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

// ── Open Library API types ────────────────────────────────────

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
