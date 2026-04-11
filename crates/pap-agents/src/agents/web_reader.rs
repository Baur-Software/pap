use pap_transport::TransportError;
use serde_json::json;

use crate::executor::{AgentExecutor, AgentMeta};

/// Web Page Reader — the zero-trust bridge agent.
///
/// Fetches any URL, strips tracking/JS, and returns clean Schema.org
/// WebPage JSON-LD. The user's ephemeral DID never touches the target
/// website — the agent infrastructure bridges to the non-zero-trust web.
///
/// Requires `schema:URL` disclosure — the user must explicitly reveal
/// what page they want read.
pub struct WebReaderExecutor;

impl AgentExecutor for WebReaderExecutor {
    fn meta(&self) -> AgentMeta {
        AgentMeta {
            name: "Web Page Reader",
            version: "0.1.0",
            provider: "Papillon",
            action: "schema:ReadAction",
            object_types: &["schema:WebPage"],
            requires_disclosure: &["schema:URL"],
            returns: &["schema:WebPage"],
            configurable_properties: vec![],
        }
    }

    fn execute(&self, query: &str) -> Result<serde_json::Value, TransportError> {
        let url = extract_url(query)
            .ok_or_else(|| TransportError::ServerError("No valid URL found in query".into()))?;

        let client = reqwest::blocking::Client::builder()
            .user_agent("Papillon/0.1 (PAP Browser; +https://pap.dev)")
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|e: reqwest::Error| TransportError::ServerError(e.to_string()))?;

        let resp = client
            .get(&url)
            .header("Accept", "text/html,application/xhtml+xml")
            .send()
            .map_err(|e: reqwest::Error| {
                TransportError::ServerError(format!("Web Reader fetch: {e}"))
            })?;

        let final_url = resp.url().to_string();
        let html = resp.text().map_err(|e: reqwest::Error| {
            TransportError::ServerError(format!("Web Reader read: {e}"))
        })?;

        let page = parse_html_to_webpage(&url, &final_url, &html);

        Ok(page)
    }
}

/// Extract a URL from the query. Handles bare URLs and "read <url>" patterns.
fn extract_url(query: &str) -> Option<String> {
    // Find the first thing that looks like a URL
    for word in query.split_whitespace() {
        if word.starts_with("http://") || word.starts_with("https://") {
            return Some(word.to_string());
        }
    }
    // Maybe the whole query is a URL without scheme
    let trimmed = query.trim();
    if trimmed.contains('.') && !trimmed.contains(' ') {
        return Some(format!("https://{trimmed}"));
    }
    None
}

/// Parse HTML into a Schema.org WebPage JSON-LD object.
///
/// Uses simple string-based extraction to avoid heavy dependencies.
/// Extracts: title, description, author, OG tags, and visible text.
fn parse_html_to_webpage(original_url: &str, final_url: &str, html: &str) -> serde_json::Value {
    let title = extract_meta(html, "og:title")
        .or_else(|| extract_html_tag(html, "title"))
        .unwrap_or_default();

    let description = extract_meta(html, "og:description")
        .or_else(|| extract_meta_name(html, "description"))
        .unwrap_or_default();

    let author = extract_meta_name(html, "author").or_else(|| extract_meta(html, "article:author"));

    let published =
        extract_meta(html, "article:published_time").or_else(|| extract_meta_name(html, "date"));

    let image = extract_meta(html, "og:image");
    let site_name = extract_meta(html, "og:site_name");

    // Extract visible text — strip all tags, limit to ~2000 chars
    let text = extract_visible_text(html);
    let text_preview = if text.len() > 2000 {
        format!("{}...", &text[..2000])
    } else {
        text
    };

    let mut page = json!({
        "@context": "https://schema.org",
        "@type": "WebPage",
        "name": title,
        "url": final_url,
        "description": description,
        "text": text_preview
    });

    if original_url != final_url {
        page["mainEntityOfPage"] = json!(original_url);
    }
    if let Some(author) = author {
        page["author"] = json!({
            "@type": "Person",
            "name": author
        });
    }
    if let Some(published) = published {
        page["datePublished"] = json!(published);
    }
    if let Some(image) = image {
        page["image"] = json!(image);
    }
    if let Some(site_name) = site_name {
        page["publisher"] = json!({
            "@type": "Organization",
            "name": site_name
        });
    }

    page
}

/// Extract content from <meta property="og:..." content="...">
fn extract_meta(html: &str, property: &str) -> Option<String> {
    let pattern = format!("property=\"{}\"", property);
    extract_meta_content(html, &pattern)
}

/// Extract content from <meta name="..." content="...">
fn extract_meta_name(html: &str, name: &str) -> Option<String> {
    let pattern = format!("name=\"{}\"", name);
    extract_meta_content(html, &pattern)
}

fn extract_meta_content(html: &str, pattern: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let pattern_lower = pattern.to_lowercase();

    let idx = lower.find(&pattern_lower)?;
    // Search for content="..." in the same <meta> tag
    let tag_start = lower[..idx].rfind('<')?;
    let tag_end = lower[idx..].find('>')? + idx;
    let tag = &html[tag_start..=tag_end];

    let content_idx = tag.to_lowercase().find("content=\"")?;
    let value_start = content_idx + 9; // len of 'content="'
    let value_end = tag[value_start..].find('"')? + value_start;

    let value = tag[value_start..value_end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(decode_html_entities(&value))
    }
}

/// Extract text content of an HTML tag: <tag>content</tag>
fn extract_html_tag(html: &str, tag: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);

    let start = lower.find(&open)?;
    let after = &html[start..];
    let content_start = after.find('>')? + 1;
    let content = &after[content_start..];
    let end = content.to_lowercase().find(&close)?;

    let text = content[..end].trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(decode_html_entities(&text))
    }
}

/// Strip HTML tags and extract visible text.
fn extract_visible_text(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    let mut i = 0;
    while i < chars.len() {
        if !in_tag && i + 7 < lower_chars.len() {
            let segment: String = lower_chars[i..i + 7].iter().collect();
            if segment == "<script" {
                in_script = true;
            }
            if segment.starts_with("<style") {
                in_style = true;
            }
        }

        if chars[i] == '<' {
            in_tag = true;

            // Check for end of script/style
            if i + 9 < lower_chars.len() {
                let segment: String = lower_chars[i..i + 9].iter().collect();
                if segment == "</script>" {
                    in_script = false;
                }
            }
            if i + 8 < lower_chars.len() {
                let segment: String = lower_chars[i..i + 8].iter().collect();
                if segment == "</style>" {
                    in_style = false;
                }
            }
        } else if chars[i] == '>' {
            in_tag = false;
        } else if !in_tag && !in_script && !in_style {
            result.push(chars[i]);
        }

        i += 1;
    }

    // Collapse whitespace
    let result = result.split_whitespace().collect::<Vec<&str>>().join(" ");

    decode_html_entities(&result)
}

/// Decode common HTML entities.
fn decode_html_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_url_bare() {
        assert_eq!(
            extract_url("https://example.com"),
            Some("https://example.com".into())
        );
    }

    #[test]
    fn extract_url_with_text() {
        assert_eq!(
            extract_url("read https://example.com/page"),
            Some("https://example.com/page".into())
        );
    }

    #[test]
    fn extract_url_no_scheme() {
        assert_eq!(
            extract_url("example.com"),
            Some("https://example.com".into())
        );
    }

    #[test]
    fn extract_url_no_url() {
        assert_eq!(extract_url("tell me a joke"), None);
    }

    #[test]
    fn parse_simple_html() {
        let html = r#"<html>
<head>
<title>Test Page</title>
<meta property="og:description" content="A test page">
<meta name="author" content="Alice">
</head>
<body>
<h1>Hello World</h1>
<p>Some content here.</p>
<script>var x = 1;</script>
</body>
</html>"#;

        let page = parse_html_to_webpage("https://example.com", "https://example.com", html);
        assert_eq!(page["name"], "Test Page");
        assert_eq!(page["description"], "A test page");
        assert_eq!(page["author"]["name"], "Alice");

        let text = page["text"].as_str().unwrap();
        assert!(text.contains("Hello World"));
        assert!(text.contains("Some content here"));
        assert!(!text.contains("var x"));
    }

    #[test]
    fn html_entities_decoded() {
        assert_eq!(decode_html_entities("A &amp; B"), "A & B");
        assert_eq!(decode_html_entities("&lt;tag&gt;"), "<tag>");
    }
}
