use pap_transport::TransportError;
use serde::Deserialize;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// GitHub Repos — public API, zero disclosure. 60 req/hr unauthenticated.
///
/// Previews the bridge pattern: an operator holding a PAT gets 5000 req/hr,
/// demonstrating how operator credentials enhance service without exposing
/// user identity.
pub struct GitHubReposExecutor;

impl AgentExecutor for GitHubReposExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "GitHub Repos",
            provider: "GitHub",
            action: "schema:SearchAction",
            object_types: &["schema:SoftwareSourceCode"],
            requires_disclosure: &[],
            returns: &["schema:SoftwareSourceCode"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp: GhSearchResponse = client
            .get("https://api.github.com/search/repositories")
            .query(&[("q", query), ("per_page", "5"), ("sort", "stars")])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("GitHub request: {e}"))
            })?
            .json()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("GitHub parse: {e}"))
            })?;

        let repos: Vec<serde_json::Value> = resp
            .items
            .into_iter()
            .map(|repo| {
                let mut item = json!({
                    "@type": "SoftwareSourceCode",
                    "name": repo.full_name,
                    "url": repo.html_url,
                    "codeRepository": repo.html_url,
                    "interactionStatistic": [{
                        "@type": "InteractionCounter",
                        "interactionType": "LikeAction",
                        "userInteractionCount": repo.stargazers_count
                    }, {
                        "@type": "InteractionCounter",
                        "interactionType": "ForkAction",
                        "userInteractionCount": repo.forks_count
                    }]
                });

                if let Some(desc) = repo.description {
                    item["description"] = json!(desc);
                }
                if let Some(lang) = repo.language {
                    item["programmingLanguage"] = json!(lang);
                }
                if let Some(license) = repo.license {
                    if let Some(name) = license.name {
                        item["license"] = json!(name);
                    }
                }
                if let Some(topics) = repo.topics {
                    if !topics.is_empty() {
                        item["keywords"] = json!(topics.join(", "));
                    }
                }

                item
            })
            .collect();

        Ok(json!({
            "@context": "https://schema.org",
            "@type": "SearchResultsPage",
            "query": query,
            "mainEntity": {
                "@type": "ItemList",
                "numberOfItems": repos.len(),
                "itemListElement": repos
            }
        }))
    }
}

#[derive(Deserialize)]
struct GhSearchResponse {
    items: Vec<GhRepo>,
}

#[derive(Deserialize)]
struct GhRepo {
    full_name: String,
    html_url: String,
    description: Option<String>,
    language: Option<String>,
    stargazers_count: u64,
    forks_count: u64,
    license: Option<GhLicense>,
    topics: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct GhLicense {
    name: Option<String>,
}
