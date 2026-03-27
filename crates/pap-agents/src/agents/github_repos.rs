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

#[cfg(test)]
mod tests {
    use super::*;

    // Real payload from https://api.github.com/search/repositories?q=rust+web+framework&per_page=1&sort=stars
    const REAL_PAYLOAD: &str = r#"{
        "total_count": 1382,
        "incomplete_results": false,
        "items": [{
            "id": 329782568,
            "node_id": "MDEwOlJlcG9zaXRvcnkzMjk3ODI1Njg=",
            "name": "dioxus",
            "full_name": "DioxusLabs/dioxus",
            "private": false,
            "owner": {
                "login": "DioxusLabs",
                "id": 79236386
            },
            "html_url": "https://github.com/DioxusLabs/dioxus",
            "description": "Fullstack app framework for web, desktop, and mobile.",
            "fork": false,
            "url": "https://api.github.com/repos/DioxusLabs/dioxus",
            "created_at": "2021-01-15T01:57:26Z",
            "updated_at": "2026-03-27T03:54:11Z",
            "pushed_at": "2026-03-27T00:14:10Z",
            "homepage": "https://dioxuslabs.com",
            "size": 51910,
            "stargazers_count": 35461,
            "watchers_count": 35461,
            "language": "Rust",
            "has_issues": true,
            "has_projects": true,
            "forks_count": 1606,
            "archived": false,
            "disabled": false,
            "open_issues_count": 672,
            "license": {
                "key": "apache-2.0",
                "name": "Apache License 2.0",
                "spdx_id": "Apache-2.0",
                "url": "https://api.github.com/licenses/apache-2.0",
                "node_id": "MDc6TGljZW5zZTI="
            },
            "topics": ["android", "css", "desktop", "html", "ios", "native", "react", "rust", "ssr", "ui", "virtualdom", "wasm", "web"],
            "visibility": "public",
            "forks": 1606,
            "watchers": 35461,
            "default_branch": "main",
            "score": 1.0
        }]
    }"#;

    #[test]
    fn deserialize_real_payload() {
        let resp: GhSearchResponse = serde_json::from_str(REAL_PAYLOAD).unwrap();
        assert_eq!(resp.items.len(), 1);

        let repo = &resp.items[0];
        assert_eq!(repo.full_name, "DioxusLabs/dioxus");
        assert_eq!(repo.html_url, "https://github.com/DioxusLabs/dioxus");
        assert_eq!(
            repo.description.as_deref(),
            Some("Fullstack app framework for web, desktop, and mobile.")
        );
        assert_eq!(repo.language.as_deref(), Some("Rust"));
        assert_eq!(repo.stargazers_count, 35461);
        assert_eq!(repo.forks_count, 1606);
        assert_eq!(
            repo.license.as_ref().unwrap().name.as_deref(),
            Some("Apache License 2.0")
        );
        assert_eq!(repo.topics.as_ref().unwrap().len(), 13);
        assert!(repo.topics.as_ref().unwrap().contains(&"rust".to_string()));
    }

    #[test]
    fn deserialize_minimal_repo() {
        // Repos can have null description, language, license, topics
        let json = r#"{
            "items": [{
                "full_name": "user/repo",
                "html_url": "https://github.com/user/repo",
                "description": null,
                "language": null,
                "stargazers_count": 0,
                "forks_count": 0,
                "license": null,
                "topics": null
            }]
        }"#;
        let resp: GhSearchResponse = serde_json::from_str(json).unwrap();
        let repo = &resp.items[0];
        assert_eq!(repo.full_name, "user/repo");
        assert!(repo.description.is_none());
        assert!(repo.language.is_none());
        assert!(repo.license.is_none());
        assert!(repo.topics.is_none());
    }
}
