//! DatasetSearchTemplate — block renderer for `schema:DatasetSearchResults`.
//!
//! Reads directly from the schema:ItemList JSON-LD content blob.
//! Provider badges use `--teal` tint for preferred agents (relevance_score > 1.1),
//! `--bg-3` for others.

use leptos::prelude::*;
use serde_json::Value;

use super::renderer::BlockRenderer;
use papillon_shared::DatasetResult;

pub struct DatasetSearchTemplate;

impl BlockRenderer for DatasetSearchTemplate {
    fn schema_types(&self) -> Vec<&'static str> {
        vec!["DatasetSearchResults"]
    }

    fn render(&self, content: &Value) -> AnyView {
        let content = content.clone();

        view! {
            <DatasetResultsView content=content />
        }
        .into_any()
    }
}

#[component]
fn DatasetResultsView(content: Value) -> impl IntoView {
    // Extract results from content (ItemList JSON-LD)
    let results = extract_results_from_content(&content);
    let result_count = results.len();

    view! {
        <div class="dataset-search-results">
            // Result count header
            <div class="dataset-results-header">
                <h3 class="dataset-results-title">
                    {result_count}
                    {if result_count == 1 { " dataset found" } else { " datasets found" }}
                </h3>
            </div>

            // Result cards
            <div class="dataset-results-list">
                {results.into_iter().map(|r| view! {
                    <DatasetResultCard result=r />
                }).collect::<Vec<_>>()}
            </div>
        </div>
    }
}

#[component]
fn DatasetResultCard(result: DatasetResult) -> impl IntoView {
    let name = result.name.clone();
    let description = result.description.clone().unwrap_or_default();
    let url = result.url.clone().unwrap_or_default();
    let source = result.source_agent.clone();
    let license = result.license.clone();
    let creator = result.creator.clone();
    let from_memex = result.from_memex;
    let relevance = result.relevance_score;

    let license_class = if license
        .as_deref()
        .map(|l| {
            let lower = l.to_lowercase();
            lower.contains("mit")
                || lower.contains("apache")
                || lower.contains("cc")
        })
        .unwrap_or(false)
    {
        "dataset-license open"
    } else if license.is_some() {
        "dataset-license restricted"
    } else {
        "dataset-license unknown"
    };

    // High preference agents get teal tint (score > 1.1 indicates established preference)
    let source_class = if relevance > 1.1 {
        "dataset-source preferred"
    } else {
        "dataset-source"
    };

    let has_url = !url.is_empty();
    let has_desc = !description.is_empty();
    let has_creator = creator.is_some();
    let has_license = license.is_some();

    let desc_truncated = if description.len() > 160 {
        format!("{}…", &description[..160])
    } else {
        description.clone()
    };

    let creator_label = creator.clone().map(|c| format!("by {c}"));
    let license_label = license.clone().unwrap_or_default();

    view! {
        <div class=format!("dataset-result-card{}", if from_memex { " from-memex" } else { "" })>
            <div class="dataset-result-header">
                {if has_url {
                    view! {
                        <a
                            href=url.clone()
                            target="_blank"
                            rel="noopener noreferrer"
                            class="dataset-result-name"
                        >
                            {name.clone()}
                        </a>
                    }.into_any()
                } else {
                    view! {
                        <span class="dataset-result-name">{name.clone()}</span>
                    }.into_any()
                }}
                {if from_memex {
                    view! { <span class="dataset-memex-label">"\u{29d7} seen"</span> }.into_any()
                } else {
                    view! { <></> }.into_any()
                }}
            </div>

            {if has_desc {
                view! {
                    <p class="dataset-result-description">{desc_truncated}</p>
                }.into_any()
            } else {
                view! { <></> }.into_any()
            }}

            <div class="dataset-result-meta">
                <span class=source_class>{source}</span>
                {if has_creator {
                    view! {
                        <span class="dataset-creator">{creator_label.unwrap_or_default()}</span>
                    }.into_any()
                } else {
                    view! { <></> }.into_any()
                }}
                {if has_license {
                    view! {
                        <span class=license_class>{license_label}</span>
                    }.into_any()
                } else {
                    view! { <></> }.into_any()
                }}
            </div>
        </div>
    }
}

/// Extract DatasetResult items from a schema:ItemList content blob.
fn extract_results_from_content(content: &Value) -> Vec<DatasetResult> {
    // Handle both direct ItemList and wrapped envelope (result.itemListElement)
    let items = if let Some(arr) = content
        .get("itemListElement")
        .and_then(|e| e.as_array())
    {
        arr.clone()
    } else if let Some(arr) = content
        .get("result")
        .and_then(|r| r.get("itemListElement"))
        .and_then(|e| e.as_array())
    {
        arr.clone()
    } else {
        return vec![];
    };

    items
        .iter()
        .filter_map(|item| {
            let item_obj = item.get("item").unwrap_or(item);
            let name = item_obj.get("name").and_then(|v| v.as_str())?;
            if name.is_empty() {
                return None;
            }
            Some(DatasetResult {
                schema_type: "Dataset".to_string(),
                name: name.to_string(),
                description: item_obj
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                url: item_obj
                    .get("url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                encoding_format: item_obj
                    .get("encodingFormat")
                    .and_then(|v| v.as_str())
                    .map(|s| vec![s.to_string()])
                    .unwrap_or_default(),
                license: item_obj
                    .get("license")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                creator: item_obj
                    .get("creator")
                    .and_then(|c| c.get("name").and_then(|n| n.as_str()))
                    .map(|s| s.to_string()),
                date_modified: item_obj
                    .get("dateModified")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                distribution: vec![],
                source_agent: item_obj
                    .get("sourceAgent")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
                source_agent_did: item_obj
                    .get("sourceAgentDid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                relevance_score: item_obj
                    .get("relevanceScore")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5),
                croissant_metadata: item_obj.get("croissantMetadata").cloned(),
                from_memex: item_obj
                    .get("fromMemex")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            })
        })
        .collect()
}
