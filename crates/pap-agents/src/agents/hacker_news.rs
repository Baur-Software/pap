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

#[cfg(test)]
mod tests {
    use super::*;

    // Real payload from https://hn.algolia.com/api/v1/search?query=rust&hitsPerPage=1
    const REAL_PAYLOAD: &str = r#"{
        "hits": [{
            "_highlightResult": {
                "author": { "matchLevel": "none", "matchedWords": [], "value": "Sikul" },
                "title": { "fullyHighlighted": false, "matchLevel": "full", "matchedWords": ["rust"], "value": "Why Discord is switching from Go to <em>rust</em>" }
            },
            "_tags": ["story", "author_Sikul", "story_22238335"],
            "author": "Sikul",
            "children": [22238816, 22239186],
            "created_at": "2020-02-04T17:30:40Z",
            "created_at_i": 1580837440,
            "num_comments": 642,
            "objectID": "22238335",
            "points": 1582,
            "story_id": 22238335,
            "title": "Why Discord is switching from Go to Rust",
            "updated_at": "2026-03-18T18:22:48Z",
            "url": "https://blog.discordapp.com/why-discord-is-switching-from-go-to-rust-a190bbca2b1f"
        }],
        "nbHits": 50000,
        "page": 0,
        "nbPages": 50,
        "hitsPerPage": 1,
        "processingTimeMS": 2
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: HnSearchResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(resp.hits.len(), 1);

        let hit = &resp.hits[0];
        assert_eq!(
            hit.title.as_deref(),
            Some("Why Discord is switching from Go to Rust")
        );
        assert_eq!(hit.author, "Sikul");
        assert_eq!(hit.points, Some(1582));
        assert_eq!(hit.object_id, "22238335");
        assert_eq!(hit.created_at, "2020-02-04T17:30:40Z");
        assert_eq!(hit.num_comments, Some(642));
        assert_eq!(
            hit.url.as_deref(),
            Some(
                "https://blog.discordapp.com/why-discord-is-switching-from-go-to-rust-a190bbca2b1f"
            )
        );
    }

    #[test]
    fn deserialize_ask_hn_no_url() {
        // Ask HN posts have no external URL
        let json = r#"{
            "hits": [{
                "author": "dang",
                "created_at": "2024-01-01T00:00:00Z",
                "objectID": "12345",
                "title": "Ask HN: What's new in Rust?",
                "points": 100,
                "num_comments": 50
            }]
        }"#;
        let resp: HnSearchResponse = serde_json::from_str(json).unwrap();
        let hit = &resp.hits[0];
        assert!(hit.url.is_none());
        assert_eq!(hit.object_id, "12345");
    }
}
