use pap_core::receipt::TransactionReceipt;
use pap_core::session::CapabilityToken;
use pap_did::SessionKeypair;
use pap_transport::{AgentHandler, TransportError};
use serde::Deserialize;
use serde_json::json;

use super::session_store::SessionStore;

/// Hacker News search agent.
///
/// Calls the HN Algolia API — zero disclosure, public API.
/// Same action type (SearchAction) as DuckDuckGo/Wikipedia but returns
/// NewsArticle objects, demonstrating multi-source federation for the same action.
/// Sessions are TTL-bounded and reaped automatically.
pub struct HackerNewsAgent {
    sessions: SessionStore<Option<String>>, // query
}

impl Default for HackerNewsAgent {
    fn default() -> Self {
        Self {
            sessions: SessionStore::new(),
        }
    }
}

impl HackerNewsAgent {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AgentHandler for HackerNewsAgent {
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

        let resp: HnSearchResponse = client
            .get("https://hn.algolia.com/api/v1/search")
            .query(&[("query", query.as_str()), ("hitsPerPage", "5")])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Hacker News request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Hacker News parse: {e}"))
            })?;

        let articles: Vec<serde_json::Value> = resp
            .hits
            .into_iter()
            .filter_map(|hit| {
                let title = hit.title?;
                let url = hit
                    .url
                    .unwrap_or_else(|| format!("https://news.ycombinator.com/item?id={}", hit.object_id));
                let discussion_url =
                    format!("https://news.ycombinator.com/item?id={}", hit.object_id);

                let mut article = json!({
                    "@type": "NewsArticle",
                    "headline": title,
                    "url": url,
                    "author": {
                        "@type": "Person",
                        "name": hit.author
                    },
                    "datePublished": hit.created_at,
                    "discussionUrl": discussion_url
                });

                if let Some(points) = hit.points {
                    article["interactionStatistic"] = json!([
                        {
                            "@type": "InteractionCounter",
                            "interactionType": "LikeAction",
                            "userInteractionCount": points
                        }
                    ]);
                    if let Some(comments) = hit.num_comments {
                        article["interactionStatistic"]
                            .as_array_mut()
                            .unwrap()
                            .push(json!({
                                "@type": "InteractionCounter",
                                "interactionType": "CommentAction",
                                "userInteractionCount": comments
                            }));
                    }
                }

                Some(article)
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "SearchResultsPage",
            "query": query,
            "mainEntity": {
                "@type": "ItemList",
                "numberOfItems": articles.len(),
                "itemListElement": articles
            }
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

// ── Hacker News Algolia API types ─────────────────────────────

#[derive(Deserialize)]
struct HnSearchResponse {
    hits: Vec<HnHit>,
}

#[derive(Deserialize)]
struct HnHit {
    title: Option<String>,
    url: Option<String>,
    author: String,
    points: Option<i32>,
    #[serde(rename = "objectID")]
    object_id: String,
    created_at: String,
    num_comments: Option<i32>,
}
