use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// Wikipedia knowledge agent.
///
/// Calls the Wikimedia REST API — zero disclosure, public API.
/// The search query arrives via `handle_disclosure` (protocol-native).
/// Sessions are TTL-bounded and reaped automatically.
pub struct WikipediaAgent {
    sessions: SessionStore<Option<String>>, // query
}

impl WikipediaAgent {
    pub fn new() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl AgentHandler for WikipediaAgent {
    fn handle_token(&self, token: CapabilityToken) -> Result<(String, String), TransportError> {
        if token.action != "schema:SearchAction" {
            return Err(TransportError::ServerError(format!(
                "Unsupported action: {}", token.action
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
        let query = self.sessions.with(session_id, |data| data.clone())?
            .ok_or_else(|| TransportError::ServerError("No query provided in disclosures".into()))?;

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser; mailto:pap@baur-software.com)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: WikiSearchResponse = client
            .get("https://en.wikipedia.org/w/rest.php/v1/search/page")
            .query(&[("q", query.as_str()), ("limit", "5")])
            .send()
            .map_err(|e: reqwest::Error| TransportError::ServerError(format!("Wikipedia request: {e}")))?
            .json()
            .map_err(|e: reqwest::Error| TransportError::ServerError(format!("Wikipedia parse: {e}")))?;

        let results: Vec<serde_json::Value> = resp
            .pages
            .into_iter()
            .map(|p| {
                let snippet = p.excerpt.or(p.description).unwrap_or_default()
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

    fn co_sign_receipt(
        &self,
        mut receipt: TransactionReceipt,
    ) -> Result<TransactionReceipt, TransportError> {
        let key = self.sessions.signing_key(
            &receipt.session_id,
        );
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
