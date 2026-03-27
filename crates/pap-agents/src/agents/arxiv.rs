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
            .user_agent("Papillon/0.1 (PAP Browser)")
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

        // Extract arXiv categories (deduplicate — primary_category repeats in category list)
        let mut seen = std::collections::HashSet::new();
        let categories: Vec<String> = entry
            .split("category term=\"")
            .skip(1)
            .filter_map(|c| c.split('"').next().map(String::from))
            .filter(|c| seen.insert(c.clone()))
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

    // Realistic arXiv Atom XML matching the real API structure (with namespace attrs,
    // multiple links, arxiv-specific tags, multiline content).
    const REAL_ARXIV_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"
      xmlns:opensearch="http://a9.com/-/spec/opensearch/1.1/"
      xmlns:arxiv="http://arxiv.org/schemas/atom">
  <opensearch:totalResults>1</opensearch:totalResults>
  <opensearch:startIndex>0</opensearch:startIndex>
  <opensearch:itemsPerPage>1</opensearch:itemsPerPage>
  <entry>
    <id>http://arxiv.org/abs/1706.03762v7</id>
    <updated>2023-08-02T12:42:38Z</updated>
    <published>2017-06-12T17:57:34Z</published>
    <title>Attention Is All You Need</title>
    <summary>  The dominant sequence transduction models are based on complex recurrent or
convolutional neural networks that include an encoder and a decoder. The best
performing models also connect the encoder and decoder through an attention
mechanism. We propose a new simple network architecture, the Transformer,
based solely on attention mechanisms, dispensing with recurrence and convolutions
entirely.  </summary>
    <author>
      <name>Ashish Vaswani</name>
    </author>
    <author>
      <name>Noam Shazeer</name>
    </author>
    <author>
      <name>Niki Parmar</name>
    </author>
    <arxiv:comment>15 pages, 5 figures</arxiv:comment>
    <link href="http://arxiv.org/abs/1706.03762v7" rel="alternate" type="text/html"/>
    <link title="pdf" href="http://arxiv.org/pdf/1706.03762v7" rel="related" type="application/pdf"/>
    <arxiv:primary_category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
    <category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
    <category term="cs.LG" scheme="http://arxiv.org/schemas/atom"/>
  </entry>
</feed>"#;

    #[test]
    fn parse_real_arxiv_entry() {
        let articles = parse_arxiv_entries(REAL_ARXIV_XML);
        assert_eq!(articles.len(), 1);

        let a = &articles[0];
        assert_eq!(a["headline"], "Attention Is All You Need");
        assert_eq!(a["datePublished"], "2017-06-12T17:57:34Z");
        // Should extract the first (alternate) link, not the PDF link
        assert_eq!(a["url"], "http://arxiv.org/abs/1706.03762v7");

        let authors = a["author"].as_array().unwrap();
        assert_eq!(authors.len(), 3);
        assert_eq!(authors[0]["name"], "Ashish Vaswani");
        assert_eq!(authors[1]["name"], "Noam Shazeer");
        assert_eq!(authors[2]["name"], "Niki Parmar");

        assert_eq!(a["keywords"], "cs.CL, cs.LG");

        // Summary should be cleaned (newlines collapsed)
        let desc = a["description"].as_str().unwrap();
        assert!(desc.contains("Transformer"));
        assert!(!desc.contains('\n'));
    }

    #[test]
    fn parse_multiple_entries() {
        let xml = r#"<feed>
<entry>
<title>Paper A</title>
<summary>Summary A</summary>
<link href="http://arxiv.org/abs/0001" rel="alternate" type="text/html"/>
<author><name>Alice</name></author>
</entry>
<entry>
<title>Paper B</title>
<summary>Summary B</summary>
<link href="http://arxiv.org/abs/0002" rel="alternate" type="text/html"/>
<author><name>Bob</name></author>
</entry>
</feed>"#;
        let articles = parse_arxiv_entries(xml);
        assert_eq!(articles.len(), 2);
        assert_eq!(articles[0]["headline"], "Paper A");
        assert_eq!(articles[1]["headline"], "Paper B");
    }

    #[test]
    fn parse_empty_feed() {
        let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
</feed>"#;
        let articles = parse_arxiv_entries(xml);
        assert!(articles.is_empty());
    }

    #[test]
    fn extract_tag_basic() {
        assert_eq!(
            extract_tag("<name>Alice</name>", "name"),
            Some("Alice".into())
        );
    }

    #[test]
    fn extract_tag_with_attrs() {
        assert_eq!(
            extract_tag("<title lang=\"en\">Hello</title>", "title"),
            Some("Hello".into())
        );
    }

    #[test]
    fn extract_attr_href() {
        let xml = r#"<link href="http://example.com" rel="alternate"/>"#;
        let values = extract_attr(xml, "link", "href").unwrap();
        assert_eq!(values, vec!["http://example.com"]);
    }
}
