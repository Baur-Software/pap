use std::collections::HashMap;
use std::sync::Mutex;

use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

struct SessionState {
    session_key: SessionKeypair,
    query: Option<String>,
}

/// Wikipedia knowledge agent.
///
/// Calls the Wikimedia REST API — zero disclosure, public API.
/// The search query arrives via `handle_disclosure` (protocol-native).
pub struct WikipediaAgent {
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl WikipediaAgent {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
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
        let session_key = SessionKeypair::generate();
        let receiver_did = session_key.did();

        self.sessions.lock().unwrap().insert(
            session_id.clone(),
            SessionState { session_key, query: None },
        );

        Ok((session_id, receiver_did))
    }

    fn handle_did_exchange(
        &self,
        session_id: &str,
        _initiator_session_did: &str,
    ) -> Result<(), TransportError> {
        if !self.sessions.lock().unwrap().contains_key(session_id) {
            return Err(TransportError::ServerError("Unknown session".into()));
        }
        Ok(())
    }

    fn handle_disclosure(
        &self,
        session_id: &str,
        disclosures: Vec<serde_json::Value>,
    ) -> Result<(), TransportError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| TransportError::ServerError("Unknown session".into()))?;

        for d in &disclosures {
            if let Some(q) = d.get("query").and_then(|v| v.as_str()) {
                session.query = Some(q.to_string());
            }
        }
        Ok(())
    }

    fn execute(&self, session_id: &str) -> Result<serde_json::Value, TransportError> {
        let query = {
            let sessions = self.sessions.lock().unwrap();
            let session = sessions
                .get(session_id)
                .ok_or_else(|| TransportError::ServerError("Unknown session".into()))?;
            session.query.clone()
                .ok_or_else(|| TransportError::ServerError("No query provided in disclosures".into()))?
        };

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser; mailto:pap@baur-software.com)")
            .build()
            .map_err(|e| TransportError::ServerError(e.to_string()))?;

        let resp: WikiSearchResponse = client
            .get("https://en.wikipedia.org/w/rest.php/v1/search/page")
            .query(&[("q", query.as_str()), ("limit", "5")])
            .send()
            .map_err(|e| TransportError::ServerError(format!("Wikipedia request: {e}")))?
            .json()
            .map_err(|e| TransportError::ServerError(format!("Wikipedia parse: {e}")))?;

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
        let sessions = self.sessions.lock().unwrap();
        let key = sessions
            .values()
            .next()
            .map(|s| s.session_key.signing_key().clone());
        drop(sessions);

        if let Some(k) = key {
            receipt.co_sign(&k);
        } else {
            let k = SessionKeypair::generate();
            receipt.co_sign(k.signing_key());
        }
        Ok(receipt)
    }

    fn handle_close(&self, session_id: &str) -> Result<(), TransportError> {
        self.sessions.lock().unwrap().remove(session_id);
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
