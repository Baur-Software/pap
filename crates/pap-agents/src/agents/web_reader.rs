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

    // Extract visible text — preserve paragraph structure, limit to ~8000 chars.
    let text = extract_visible_text(html);
    let text_preview = if text.len() > 8000 {
        // Slice at a char boundary to avoid panics on multibyte characters.
        let cutoff = text
            .char_indices()
            .nth(8000)
            .map(|(i, _)| i)
            .unwrap_or(text.len());
        format!("{}...", &text[..cutoff])
    } else {
        text
    };

    // Extract up to 12 same-origin links as schema:WebPage mentions.
    let mentions = extract_mentions(html, &final_url);

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
    if !mentions.is_empty() {
        page["mentions"] = serde_json::Value::Array(mentions);
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

/// Strip HTML tags and extract visible text, preserving paragraph structure.
///
/// Block-level closing tags (`</p>`, `</div>`, headings, `</li>`, etc.) emit a
/// double newline so the rendered text has readable paragraph breaks instead of
/// a single long blob.  `<br>` emits a single newline.
fn extract_visible_text(html: &str) -> String {
    let mut result = String::new();
    let mut in_tag = false;
    let mut in_script = false;
    let mut in_style = false;
    // Buffer enough of the current tag to identify its name (≤32 chars).
    let mut tag_buf = String::new();
    let lower = html.to_lowercase();
    let chars: Vec<char> = html.chars().collect();
    let lower_chars: Vec<char> = lower.chars().collect();

    let is_block = |tag: &str| -> bool {
        matches!(
            tag,
            "p" | "div"
                | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
                | "li"
                | "ul"
                | "ol"
                | "article"
                | "section"
                | "blockquote"
                | "header"
                | "footer"
                | "main"
                | "nav"
                | "aside"
                | "tr"
                | "td"
                | "th"
        )
    };

    let mut i = 0;
    while i < chars.len() {
        // Detect script/style open tags before entering the tag
        if !in_tag && i + 7 < lower_chars.len() {
            let seg: String = lower_chars[i..i + 7].iter().collect();
            if seg == "<script" {
                in_script = true;
            }
            if seg.starts_with("<style") {
                in_style = true;
            }
        }

        if chars[i] == '<' {
            in_tag = true;
            tag_buf.clear();

            // Detect script/style close
            if i + 9 < lower_chars.len() {
                let seg: String = lower_chars[i..i + 9].iter().collect();
                if seg == "</script>" {
                    in_script = false;
                }
            }
            if i + 8 < lower_chars.len() {
                let seg: String = lower_chars[i..i + 8].iter().collect();
                if seg == "</style>" {
                    in_style = false;
                }
            }
        } else if chars[i] == '>' {
            if !in_script && !in_style {
                let trimmed = tag_buf.trim_start();
                let is_closing = trimmed.starts_with('/');
                let tag_name = trimmed
                    .trim_start_matches('/')
                    .split(|c: char| !c.is_alphanumeric())
                    .next()
                    .unwrap_or("");
                if is_closing && is_block(tag_name) {
                    // Paragraph break after block-level element
                    result.push('\n');
                    result.push('\n');
                } else if tag_name == "br" {
                    result.push('\n');
                }
            }
            in_tag = false;
            tag_buf.clear();
        } else if in_tag {
            if tag_buf.len() < 32 {
                tag_buf.push(lower_chars[i]);
            }
        } else if !in_script && !in_style {
            result.push(chars[i]);
        }

        i += 1;
    }

    // Normalize: collapse whitespace within each line, deduplicate blank lines.
    let mut out = String::new();
    let mut last_was_blank = false;
    for part in result.split('\n') {
        let line = part.split_whitespace().collect::<Vec<&str>>().join(" ");
        if line.is_empty() {
            if !last_was_blank {
                out.push('\n');
                out.push('\n');
                last_was_blank = true;
            }
        } else {
            last_was_blank = false;
            out.push_str(&line);
            out.push('\n');
        }
    }

    decode_html_entities(out.trim())
}

/// Extract up to `limit` same-origin `<a href>` links as schema:WebPage objects.
///
/// Only links that share scheme+host with `base_url` are included — this gives
/// the user the navigation graph for the current site without leaking off-site
/// destinations into the JSON-LD.
fn extract_mentions(html: &str, base_url: &str) -> Vec<serde_json::Value> {
    let base_origin = url_origin(base_url);
    if base_origin.is_empty() {
        return Vec::new();
    }

    let lower = html.to_lowercase();
    let mut mentions = Vec::new();
    let mut pos = 0;

    while mentions.len() < 12 {
        // Find the start of the next <a … > opening tag
        let rel = match lower[pos..]
            .find("<a ")
            .or_else(|| lower[pos..].find("<a\t"))
        {
            Some(p) => p,
            None => break,
        };
        let tag_start = pos + rel;

        // Find the end of the opening tag
        let tag_end = match lower[tag_start..].find('>') {
            Some(e) => tag_start + e,
            None => break,
        };

        let tag_html = &html[tag_start..=tag_end];
        let tag_lower = &lower[tag_start..=tag_end];

        if let Some(href) = extract_attr_value(tag_html, tag_lower, "href") {
            let abs_url = resolve_url(&href, base_url);
            let link_origin = url_origin(&abs_url);

            if !abs_url.is_empty() && abs_url != base_url && link_origin == base_origin {
                // Extract link text (everything between <a ...> and </a>)
                let content_start = tag_end + 1;
                let name = match lower[content_start..].find("</a>") {
                    Some(end_rel) => {
                        let raw = &html[content_start..content_start + end_rel];
                        strip_inner_tags(raw).trim().to_string()
                    }
                    None => String::new(),
                };
                let name = if name.is_empty() {
                    abs_url.clone()
                } else {
                    name
                };
                mentions.push(serde_json::json!({
                    "@type": "WebPage",
                    "name": name,
                    "url": abs_url
                }));
            }
        }

        pos = tag_end + 1;
    }

    mentions
}

/// Return the scheme+host portion of a URL, e.g. `"https://example.com"`.
fn url_origin(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        let host_end = after.find('/').unwrap_or(after.len());
        format!("{}://{}", &url[..scheme_end], &after[..host_end])
    } else {
        String::new()
    }
}

/// Resolve a (potentially relative) href against a base URL.
/// Returns an empty string for fragments, mailto:, javascript:, etc.
fn resolve_url(href: &str, base: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        href.to_string()
    } else if href.starts_with('/') {
        format!("{}{}", url_origin(base), href)
    } else if href.starts_with('#')
        || href.starts_with("javascript:")
        || href.starts_with("mailto:")
        || href.starts_with("tel:")
    {
        String::new()
    } else {
        // Relative path — skip for simplicity
        String::new()
    }
}

/// Extract the value of an HTML attribute from a tag string.
/// Both `tag_html` (original case) and `tag_lower` (lowercased) must be provided.
fn extract_attr_value(tag_html: &str, tag_lower: &str, attr: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr);
    let idx = tag_lower.find(&pattern)?;
    let value_start = idx + pattern.len();
    let value_end = tag_html[value_start..].find('"')? + value_start;
    let value = tag_html[value_start..value_end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(decode_html_entities(&value))
    }
}

/// Strip HTML tags from a fragment (used to clean link text).
fn strip_inner_tags(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(c);
        }
    }
    out
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
