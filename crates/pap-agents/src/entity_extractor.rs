//! `EntityExtractor` — resolves URL template `{param}` placeholders from
//! natural-language queries.
//!
//! Strategy:
//! 1. Parse all `{name}` placeholders from the URL template (excluding `{query}`).
//! 2. Filter out auth params (those come from the SD-JWT credential vault).
//! 3. Try LLM structured-JSON extraction first when an LLM is configured.
//! 4. Fall back to deterministic regex heuristics.
//!
//! # Auth param exclusion
//!
//! [`AUTH_PARAMS`] lists all parameter names treated as credentials.
//! [`extract_heuristic`] returns `None` for every name in that list so
//! they are never populated from user input.

use std::collections::HashMap;

use crate::llm::LlmClient;

/// Parameter names that are always sourced from the SD-JWT credential vault,
/// never from the user query.  Referenced by catalog validation tests (Task 7).
pub const AUTH_PARAMS: &[&str] = &[
    "api_key",
    "apikey",
    "access_key",
    "key",
    "token",
    "api_token",
    "consumer_key",
    "user_key",
    "wskey",
    "access_token",
];

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Return `true` if `name` is an auth / credential parameter.
fn is_auth_param(name: &str) -> bool {
    AUTH_PARAMS.contains(&name)
}

// ─── public free functions ────────────────────────────────────────────────────

/// Extract all `{name}` placeholder names from `url_template`, excluding
/// `{query}`.  The returned list is deduplicated and preserves first-seen order.
pub fn extract_template_params(url_template: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    let mut chars = url_template.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c == '{' {
            let name: String = chars
                .by_ref()
                .map(|(_, c)| c)
                .take_while(|&c| c != '}')
                .collect();
            if !name.is_empty() && name != "query" && seen.insert(name.clone()) {
                result.push(name);
            }
        }
    }
    result
}

/// Extract a single parameter value from `query` using pattern-matching
/// heuristics.
///
/// Returns `None` for auth parameters (they must come from the credential
/// vault) and for any case where a reliable value cannot be determined.
/// For unrecognised parameter names the full query is returned verbatim —
/// BM25 routing already selected the right agent so the query itself is the
/// best available value.
pub fn extract_heuristic(name: &str, query: &str) -> Option<String> {
    // Auth params are always excluded.
    if is_auth_param(name) {
        return None;
    }

    match name {
        // ── Geo coordinates ───────────────────────────────────────────────
        "lat" | "latitude" => {
            // Expect "lat,lon" coordinate pair.
            let (lat_str, _) = split_coord_pair(query)?;
            let val: f64 = lat_str.parse().ok()?;
            if !(-90.0..=90.0).contains(&val) {
                return None;
            }
            Some(lat_str.to_string())
        }
        "lon" | "lng" | "longitude" => {
            let (_, lon_str) = split_coord_pair(query)?;
            let val: f64 = lon_str.parse().ok()?;
            if !(-180.0..=180.0).contains(&val) {
                return None;
            }
            Some(lon_str.to_string())
        }

        // ── GitHub-style owner/repo ───────────────────────────────────────
        "owner" => {
            let (owner, _) = parse_owner_repo(query)?;
            Some(owner.to_string())
        }
        "repo" => {
            let (_, repo) = parse_owner_repo(query)?;
            Some(repo.to_string())
        }

        // ── Reddit subreddit ─────────────────────────────────────────────
        "subreddit" => {
            let q = query.trim();
            // Strip optional "r/" prefix.
            let name_part = if let Some(stripped) = q.strip_prefix("r/") {
                stripped
            } else {
                q
            };
            // Use first whitespace-delimited token.
            let token = name_part.split_whitespace().next().unwrap_or(name_part);
            if token.is_empty() {
                None
            } else {
                Some(token.to_string())
            }
        }

        // ── Music: "Artist - Title" ───────────────────────────────────────
        "artist" => {
            let (artist, _) = split_artist_title(query)?;
            Some(artist.trim().to_string())
        }
        "title" => {
            let (_, title) = split_artist_title(query)?;
            Some(title.trim().to_string())
        }

        // ── Transit: "Origin to Destination" ─────────────────────────────
        "origin" | "oName" => {
            let (origin, _) = split_origin_destination(query)?;
            Some(origin.trim().to_string())
        }
        "destination" | "dName" => {
            let (_, dest) = split_origin_destination(query)?;
            Some(dest.trim().to_string())
        }

        // ── Year ──────────────────────────────────────────────────────────
        "year" => extract_year(query),

        // ── Verbatim fallback ─────────────────────────────────────────────
        _ => Some(query.to_string()),
    }
}

// ─── private helpers ──────────────────────────────────────────────────────────

/// Split a `"lat,lon"` coordinate string into `(lat, lon)` string slices.
fn split_coord_pair(s: &str) -> Option<(&str, &str)> {
    let mut parts = s.splitn(2, ',');
    let lat = parts.next()?.trim();
    let lon = parts.next()?.trim();
    if lat.is_empty() || lon.is_empty() {
        None
    } else {
        Some((lat, lon))
    }
}

/// Parse owner and repo from formats like:
/// - `"torvalds/linux"`
/// - `"github.com/torvalds/linux"`
fn parse_owner_repo(query: &str) -> Option<(&str, &str)> {
    // Strip a leading hostname (e.g. "github.com/") if present.
    let path = if let Some(slash_pos) = query.find("//") {
        // Absolute URL like "https://github.com/owner/repo"
        let after_scheme = &query[slash_pos + 2..];
        after_scheme
            .split_once('/')
            .map(|x| x.1)
            .unwrap_or(after_scheme)
    } else {
        // May be "github.com/owner/repo" or plain "owner/repo".
        // Only treat the first segment as a hostname when it *both* contains
        // a dot *and* is followed by a slash — i.e. the pattern is
        // "hostname/owner/repo" with at least 3 slash-delimited segments.
        // This avoids incorrectly stripping "owner.name" as a hostname.
        if query.contains('/') {
            let first_slash = query.find('/')?;
            let first_segment = &query[..first_slash];
            if first_segment.contains('.') {
                // First segment looks like a hostname — skip it.
                &query[first_slash + 1..]
            } else {
                query
            }
        } else {
            query
        }
    };

    let mut parts = path.splitn(2, '/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim().split('/').next()?; // only first segment
    if owner.is_empty() || repo.is_empty() {
        None
    } else {
        Some((owner, repo))
    }
}

/// Split `"Artist - Title"` on the first ` - ` separator.
fn split_artist_title(s: &str) -> Option<(&str, &str)> {
    s.find(" - ").map(|pos| (&s[..pos], &s[pos + 3..]))
}

/// Split `"Origin to Destination"` case-insensitively on ` to `.
fn split_origin_destination(s: &str) -> Option<(&str, &str)> {
    // Find " to " in the lowercased copy for case-insensitive matching.
    // Guard with is_char_boundary before slicing the original `s` to avoid
    // panics when multibyte characters appear before the separator.
    let lower = s.to_lowercase();
    let needle = " to ";
    let pos = lower.find(needle)?;
    let end = pos + needle.len();
    if !s.is_char_boundary(pos) || !s.is_char_boundary(end) {
        return None;
    }
    let origin = s[..pos].trim();
    let dest = s[end..].trim();
    if origin.is_empty() || dest.is_empty() {
        return None;
    }
    Some((origin, dest))
}

/// Extract the first 4-digit year from a string.
fn extract_year(s: &str) -> Option<String> {
    let mut chars = s.chars().peekable();
    let mut buf = String::new();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            buf.push(c);
            if buf.len() == 4 {
                // Verify it looks like a year (not followed by more digits).
                match chars.peek() {
                    Some(next) if next.is_ascii_digit() => {
                        // More than 4 consecutive digits — skip this run.
                        // Consume remaining digits.
                        while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                            chars.next();
                        }
                        buf.clear();
                    }
                    _ => return Some(buf),
                }
            }
        } else {
            buf.clear();
        }
    }
    None
}

// ─── EntityExtractor struct ───────────────────────────────────────────────────

/// Resolves URL template placeholders from natural-language queries.
///
/// Uses LLM structured-JSON extraction when available, falling back to
/// deterministic regex heuristics.  Auth params are always excluded.
pub struct EntityExtractor {
    llm: Box<dyn LlmClient>,
}

impl EntityExtractor {
    /// Create a new extractor backed by the given LLM client.
    pub fn new(llm: Box<dyn LlmClient>) -> Self {
        Self { llm }
    }

    /// Resolve all non-auth `{param}` placeholders in `url_template` from
    /// the natural-language `query`.
    ///
    /// Returns an empty map when the template contains no structural params.
    pub fn resolve(&self, url_template: &str, query: &str) -> HashMap<String, String> {
        let params = extract_template_params(url_template);
        // Filter auth params.
        let structural: Vec<&str> = params
            .iter()
            .map(String::as_str)
            .filter(|n| !is_auth_param(n))
            .collect();

        if structural.is_empty() {
            return HashMap::new();
        }

        // Try LLM first.
        if let Ok(llm_result) = self.extract_with_llm(&structural, query) {
            if !llm_result.is_empty() {
                return llm_result;
            }
        }

        // Heuristic fallback.
        structural
            .iter()
            .filter_map(|name| extract_heuristic(name, query).map(|v| (name.to_string(), v)))
            .collect()
    }

    /// Like `resolve` but takes param names directly instead of parsing a URL template.
    /// Used when the caller already knows which params are needed and has already
    /// pre-filled higher-priority sources — avoids redundant LLM calls for those.
    pub fn resolve_params(&self, params: &[String], query: &str) -> HashMap<String, String> {
        let structural_params: Vec<&str> = params
            .iter()
            .map(|s| s.as_str())
            .filter(|name| !is_auth_param(name))
            .collect();

        if structural_params.is_empty() {
            return HashMap::new();
        }

        if let Ok(extracted) = self.extract_with_llm(&structural_params, query) {
            if !extracted.is_empty() {
                return extracted;
            }
        }

        structural_params
            .iter()
            .filter_map(|&name| extract_heuristic(name, query).map(|v| (name.to_string(), v)))
            .collect()
    }

    /// Ask the LLM to extract structured values for the given param names.
    fn extract_with_llm(
        &self,
        params: &[&str],
        query: &str,
    ) -> Result<HashMap<String, String>, String> {
        let param_list = params
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");

        // Build a concrete example for the two most common structural params.
        let example_hint = if params.contains(&"owner") && params.contains(&"repo") {
            r#"Example for params [owner, repo] and query "torvalds/linux": {"owner":"torvalds","repo":"linux"}"#.to_string()
        } else {
            format!(
                "Example for params [{params}] and query \"some input\": {{{example}}}",
                params = params.join(", "),
                example = params
                    .iter()
                    .map(|p| format!("\"{p}\":\"<value>\""))
                    .collect::<Vec<_>>()
                    .join(","),
            )
        };

        let instructions = format!(
            "Extract the following named values from the user query. \
             Output ONLY a JSON object with these exact keys: [{param_list}]. \
             If a value cannot be determined, omit that key. \
             Do not add any other keys or explanation.\n{example_hint}"
        );

        let raw = self
            .llm
            .complete(&instructions, query)
            .map_err(|e| e.to_string())?;

        // Strip markdown fences.
        let cleaned = raw
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        let json: serde_json::Value =
            serde_json::from_str(cleaned).map_err(|e| format!("json parse: {e}"))?;

        let obj = json
            .as_object()
            .ok_or_else(|| "LLM did not return a JSON object".to_string())?;

        let mut result = HashMap::new();
        for name in params {
            if let Some(val) = obj.get(*name).and_then(|v| v.as_str()) {
                if !val.is_empty() {
                    result.insert(name.to_string(), val.to_string());
                }
            }
        }

        if result.is_empty() {
            return Err("LLM returned empty result".into());
        }

        Ok(result)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_heuristic — auth params ──────────────────────────────────────

    #[test]
    fn auth_params_return_none() {
        for name in AUTH_PARAMS {
            assert_eq!(
                extract_heuristic(name, "any text"),
                None,
                "auth param '{name}' should return None"
            );
        }
    }

    // ── extract_heuristic — geo ───────────────────────────────────────────────

    #[test]
    fn lat_from_coord_pair() {
        assert_eq!(
            extract_heuristic("lat", "37.7749,-122.4194"),
            Some("37.7749".to_string())
        );
    }

    #[test]
    fn lon_from_coord_pair() {
        assert_eq!(
            extract_heuristic("lon", "37.7749,-122.4194"),
            Some("-122.4194".to_string())
        );
    }

    // ── extract_heuristic — owner / repo ─────────────────────────────────────

    #[test]
    fn owner_repo_from_slash() {
        assert_eq!(
            extract_heuristic("owner", "torvalds/linux"),
            Some("torvalds".to_string())
        );
        assert_eq!(
            extract_heuristic("repo", "torvalds/linux"),
            Some("linux".to_string())
        );
    }

    #[test]
    fn owner_repo_with_github_prefix() {
        assert_eq!(
            extract_heuristic("owner", "github.com/rust-lang/rust"),
            Some("rust-lang".to_string())
        );
        assert_eq!(
            extract_heuristic("repo", "github.com/rust-lang/rust"),
            Some("rust".to_string())
        );
    }

    // ── extract_heuristic — subreddit ────────────────────────────────────────

    #[test]
    fn subreddit_with_r_prefix() {
        assert_eq!(
            extract_heuristic("subreddit", "r/rust"),
            Some("rust".to_string())
        );
    }

    // ── extract_heuristic — artist / title ───────────────────────────────────

    #[test]
    fn artist_title_from_dash() {
        assert_eq!(
            extract_heuristic("artist", "Pink Floyd - Comfortably Numb"),
            Some("Pink Floyd".to_string())
        );
        assert_eq!(
            extract_heuristic("title", "Pink Floyd - Comfortably Numb"),
            Some("Comfortably Numb".to_string())
        );
    }

    // ── extract_heuristic — origin / destination ─────────────────────────────

    #[test]
    fn origin_destination_from_to() {
        assert_eq!(
            extract_heuristic("origin", "London to Paris"),
            Some("London".to_string())
        );
        assert_eq!(
            extract_heuristic("destination", "London to Paris"),
            Some("Paris".to_string())
        );
    }

    // ── extract_heuristic — year ─────────────────────────────────────────────

    #[test]
    fn year_from_natural_language() {
        assert_eq!(
            extract_heuristic("year", "treasury rates 2023"),
            Some("2023".to_string())
        );
    }

    // ── extract_heuristic — verbatim fallback ────────────────────────────────

    #[test]
    fn unknown_param_returns_verbatim() {
        assert_eq!(
            extract_heuristic("country", "Germany"),
            Some("Germany".to_string())
        );
    }

    // ── extract_template_params ───────────────────────────────────────────────

    #[test]
    fn extract_params_excludes_query() {
        assert_eq!(
            extract_template_params("https://example.com/search?q={query}"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn extract_params_lat_lon() {
        let params = extract_template_params("https://api.example.com/weather?lat={lat}&lon={lon}");
        assert_eq!(params, vec!["lat", "lon"]);
    }

    #[test]
    fn extract_params_owner_repo() {
        let params = extract_template_params("https://api.github.com/{owner}/{repo}/releases");
        assert_eq!(params, vec!["owner", "repo"]);
    }

    #[test]
    fn extract_params_deduplicates() {
        let params = extract_template_params("https://api.example.com/{id}?related={id}");
        assert_eq!(params, vec!["id"]);
    }
}
