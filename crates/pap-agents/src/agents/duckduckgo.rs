use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// DuckDuckGo web search — zero disclosure, no tracking.
pub struct DuckDuckGoExecutor;

impl AgentExecutor for DuckDuckGoExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "DuckDuckGo Search",
            provider: "DuckDuckGo",
            action: "schema:SearchAction",
            object_types: &["schema:WebPage"],
            requires_disclosure: &[],
            returns: &["schema:SearchResult"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: DdgResponse = client
            .get("https://api.duckduckgo.com/")
            .query(&[
                ("q", query),
                ("format", "json"),
                ("no_html", "1"),
                ("skip_disambig", "1"),
            ])
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
}

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
        if out.len() >= 10 {
            return;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    // Real-format DDG Instant Answer payload
    const REAL_PAYLOAD: &str = r#"{
        "AbstractText": "Rust is a multi-paradigm, general-purpose programming language.",
        "AbstractURL": "https://en.wikipedia.org/wiki/Rust_(programming_language)",
        "AbstractSource": "Wikipedia",
        "RelatedTopics": [
            {
                "Text": "Rust (programming language) A systems programming language",
                "FirstURL": "https://duckduckgo.com/Rust_(programming_language)"
            },
            {
                "Name": "See also",
                "Topics": [
                    {
                        "Text": "Cargo (Rust) The Rust package manager",
                        "FirstURL": "https://duckduckgo.com/Cargo_(Rust)"
                    }
                ]
            }
        ],
        "Heading": "Rust (programming language)",
        "Answer": "",
        "Type": "A",
        "Image": "",
        "Redirect": ""
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: DdgResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(resp.abstract_source, "Wikipedia");
        assert!(resp.abstract_text.contains("multi-paradigm"));
        assert_eq!(
            resp.abstract_url,
            "https://en.wikipedia.org/wiki/Rust_(programming_language)"
        );
        assert_eq!(resp.related_topics.len(), 2);
    }

    #[test]
    fn collect_topics_flattens_groups() {
        let resp: DdgResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        let mut out = Vec::new();
        collect_topics(&resp.related_topics, &mut out);
        // 1 direct result + 1 from nested group
        assert_eq!(out.len(), 2);
        assert!(out[0]["description"]
            .as_str()
            .unwrap()
            .contains("systems programming"));
        assert!(out[1]["description"]
            .as_str()
            .unwrap()
            .contains("package manager"));
    }

    #[test]
    fn deserialize_empty_response() {
        let json = r#"{
            "AbstractText": "",
            "AbstractURL": "",
            "AbstractSource": "",
            "RelatedTopics": []
        }"#;
        let resp: DdgResponse = serde_json::from_str(json).unwrap();
        assert!(resp.abstract_text.is_empty());
        assert!(resp.related_topics.is_empty());
    }
}
