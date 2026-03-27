use pap_transport::TransportError;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// arXiv Papers — zero disclosure, public Atom API for academic papers.
///
/// Parses Atom XML with simple string extraction (no XML crate dependency).
pub struct ArxivExecutor;

impl AgentExecutor for ArxivExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "arXiv Papers",
            provider: "arxiv.org",
            action: "schema:SearchAction",
            object_types: &["schema:ScholarlyArticle"],
            requires_disclosure: &[],
            returns: &["schema:ScholarlyArticle"],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillion/0.1 (PAP Browser)")
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let xml = client
            .get("https://export.arxiv.org/api/query")
            .query(&[
                ("search_query", &format!("all:{query}")),
                ("max_results", &"5".to_string()),
                ("sortBy", &"relevance".to_string()),
            ])
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("arXiv request: {e}"))
            })?
            .text()
            .map_err(|e: reqwest::Error| TransportError::ServerError(format!("arXiv read: {e}")))?;

        let articles = parse_arxiv_entries(&xml);

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

/// Extract papers from arXiv Atom XML using simple string parsing.
fn parse_arxiv_entries(xml: &str) -> Vec<serde_json::Value> {
    let mut articles = Vec::new();

    // Split on <entry> tags to get individual papers
    for entry in xml.split("<entry>").skip(1) {
        let title = extract_tag(entry, "title").map(|t| t.replace('\n', " ").trim().to_string());
        let summary =
            extract_tag(entry, "summary").map(|s| s.replace('\n', " ").trim().to_string());
        let published = extract_tag(entry, "published");
        let url = extract_attr(entry, "link", "href").and_then(|links| links.into_iter().next());

        // Extract authors
        let authors: Vec<String> = entry
            .split("<author>")
            .skip(1)
            .filter_map(|a| extract_tag(a, "name"))
            .collect();

        // Extract arXiv categories
        let categories: Vec<String> = entry
            .split("category term=\"")
            .skip(1)
            .filter_map(|c| c.split('"').next().map(String::from))
            .collect();

        if let Some(title) = title {
            let mut article = json!({
                "@type": "ScholarlyArticle",
                "headline": title,
                "author": authors.iter().map(|a| json!({
                    "@type": "Person",
                    "name": a
                })).collect::<Vec<_>>()
            });

            if let Some(url) = url {
                article["url"] = json!(url);
            }
            if let Some(summary) = summary {
                // Truncate long abstracts
                let desc = if summary.len() > 500 {
                    format!("{}...", &summary[..500])
                } else {
                    summary
                };
                article["description"] = json!(desc);
            }
            if let Some(published) = published {
                article["datePublished"] = json!(published);
            }
            if !categories.is_empty() {
                article["keywords"] = json!(categories.join(", "));
            }

            articles.push(article);
        }
    }

    articles
}

/// Extract text between XML tags: <tag>...</tag>
fn extract_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end = content.find(&close)?;

    Some(content[..end].to_string())
}

/// Extract attribute values from tags: <tag attr="value">
fn extract_attr(xml: &str, tag: &str, attr: &str) -> Option<Vec<String>> {
    let pattern = format!("<{}", tag);
    let attr_pattern = format!("{}=\"", attr);

    let values: Vec<String> = xml
        .split(&pattern)
        .skip(1)
        .filter_map(|segment| {
            let end = segment.find('>')?;
            let tag_content = &segment[..end];
            let attr_start = tag_content.find(&attr_pattern)?;
            let value_start = attr_start + attr_pattern.len();
            let value_end = tag_content[value_start..].find('"')?;
            Some(tag_content[value_start..value_start + value_end].to_string())
        })
        .collect();

    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_arxiv_atom() {
        let xml = r#"<?xml version="1.0"?>
<feed>
<entry>
<title>Attention Is All You Need</title>
<summary>We propose a new architecture...</summary>
<published>2017-06-12T00:00:00Z</published>
<link href="https://arxiv.org/abs/1706.03762" rel="alternate" type="text/html"/>
<author><name>Ashish Vaswani</name></author>
<author><name>Noam Shazeer</name></author>
<category term="cs.CL"/>
<category term="cs.LG"/>
</entry>
</feed>"#;

        let articles = parse_arxiv_entries(xml);
        assert_eq!(articles.len(), 1);
        assert_eq!(articles[0]["headline"], "Attention Is All You Need");
        assert_eq!(articles[0]["author"].as_array().unwrap().len(), 2);
        assert_eq!(articles[0]["keywords"], "cs.CL, cs.LG");
    }
}
