use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// DuckDuckGo web search agent.
///
/// Calls the DuckDuckGo Instant Answer JSON API — zero disclosure, no tracking.
/// The search query arrives via `handle_disclosure` (protocol-native).
/// Sessions are TTL-bounded and reaped automatically.
pub struct DuckDuckGoAgent {
    sessions: SessionStore<Option<String>>, // query
}

impl DuckDuckGoAgent {
    pub fn new() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl AgentHandler for DuckDuckGoAgent {
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
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: DdgResponse = client
            .get("https://api.duckduckgo.com/")
            .query(&[("q", query.as_str()), ("format", "json"), ("no_html", "1"), ("skip_disambig", "1")])
            .send()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?
            .json()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let mut results = Vec::new();
        if !resp.abstract_text.is_empty() {
            results.push(json!({
                "@type": "SearchResult",
                "name": resp.abstract_source,
                "url": resp.abstract_url,
                "description": resp.abstract_text
            }));
        }
        collect_topics(&resp.related_topics, &mut results);

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
        // Try to find any active session key; fall back to ephemeral
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

// ── DuckDuckGo API types ────────────────────────────────────

#[derive(Deserialize)]
struct DdgResponse {
    #[serde(rename = "AbstractText")]
    abstract_text: String,
    #[serde(rename = "AbstractURL")]
    abstract_url: String,
    #[serde(rename = "AbstractSource")]
    abstract_source: String,
    #[serde(rename = "RelatedTopics")]
    related_topics: Vec<DdgTopic>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DdgTopic {
    Result {
        #[serde(rename = "Text")]
        text: String,
        #[serde(rename = "FirstURL")]
        first_url: String,
    },
    Group {
        #[serde(rename = "Topics")]
        topics: Vec<DdgTopic>,
        #[serde(rename = "Name")]
        _name: String,
    },
}

fn collect_topics(topics: &[DdgTopic], out: &mut Vec<serde_json::Value>) {
    for topic in topics {
        if out.len() >= 10 { return; }
        match topic {
            DdgTopic::Result { text, first_url } => {
                out.push(json!({
                    "@type": "SearchResult",
                    "name": text.chars().take(80).collect::<String>(),
                    "url": first_url,
                    "description": text
                }));
            }
            DdgTopic::Group { topics, .. } => collect_topics(topics, out),
        }
    }
}
