use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Hacker News search — zero disclosure, public Algolia API.
pub struct HackerNewsExecutor;

impl AgentExecutor for HackerNewsExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Hacker News",
            provider: "Y Combinator",
            action: "schema:SearchAction",
            object_types: &["schema:NewsArticle"],
            requires_disclosure: &[],
            returns: &["schema:NewsArticle"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: HnSearchResponse = client
            .get("https://hn.algolia.com/api/v1/search")
            .query(&[("query", query), ("hitsPerPage", "5")])
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
                let url = hit.url.unwrap_or_else(|| {
                    format!("https://news.ycombinator.com/item?id={}", hit.object_id)
                });
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
}

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
