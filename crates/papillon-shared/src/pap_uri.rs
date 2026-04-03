use std::collections::HashMap;

/// Where a `pap://` link originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkOrigin {
    /// Typed directly by the principal (palette, address bar).
    Principal,
    /// Embedded in an agent-rendered JSON-LD block.
    Agent,
}

/// Resolved form of a `pap://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedUri {
    /// Already a `did:key:` form — pass to backend as-is.
    Did(String),
    /// Registry hostname form — pass to backend as-is.
    Registry(String),
    /// Natural-language intent derived from a special authority.
    LocalIntent(String),
}

/// Resolution failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PapUriError {
    /// Agent-rendered link tried to activate a special authority.
    Reserved,
    /// `pap+https://` or `pap+wss://` enforcement is not built in v1.0.
    RecaptureDeferred,
    /// Catalog miss — no agent with this name in the local catalog.
    NotFound(String),
    /// URI could not be parsed.
    ParseError(String),
}

const RESERVED: &[&str] = &["receipt", "canvas", "settings"];

pub fn resolve_pap_uri(
    uri: &str,
    catalog: &HashMap<String, String>,
    origin: LinkOrigin,
) -> Result<ResolvedUri, PapUriError> {
    if uri.starts_with("pap+https://") || uri.starts_with("pap+wss://") {
        return Err(PapUriError::RecaptureDeferred);
    }

    let rest = uri
        .strip_prefix("pap://")
        .ok_or_else(|| PapUriError::ParseError(format!("not a pap:// URI: {}", uri)))?;

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    if authority.is_empty() {
        return Err(PapUriError::ParseError("empty authority".into()));
    }

    let authority_lower = authority.to_lowercase();

    // Step 0: special authorities
    if RESERVED.contains(&authority_lower.as_str()) {
        if origin == LinkOrigin::Agent {
            return Err(PapUriError::Reserved);
        }
        return Ok(ResolvedUri::LocalIntent(special_to_intent(
            &authority_lower,
            path,
        )));
    }

    // Step 1: did:key: authority (case-insensitive match to match Step 0 behaviour)
    if authority_lower.starts_with("did:key:") {
        return Ok(ResolvedUri::Did(uri.to_string()));
    }

    // Step 2: catalog name (no dot in authority, not a registry host)
    if !is_registry_host(authority) {
        if let Some(did) = catalog.get(authority_lower.as_str()) {
            // Reject path traversal before rewriting.
            // Check both literal ".." and common percent-encoded forms.
            if path.split('/').any(is_dotdot) {
                return Err(PapUriError::ParseError("path traversal not allowed".into()));
            }
            // Strip control characters from the path before constructing the
            // rewritten DID URI.  Special-authority paths are sanitized in
            // special_to_intent; catalog-rewrite paths need the same treatment.
            let safe_path: String = path.chars().filter(|c| !c.is_control()).collect();
            let rewritten = format!("pap://{}{}", did, safe_path);
            return Ok(ResolvedUri::Did(rewritten));
        }
        return Err(PapUriError::NotFound(authority_lower));
    }

    // Step 3: registry hostname / localhost / IPv4
    Ok(ResolvedUri::Registry(uri.to_string()))
}

fn is_registry_host(authority: &str) -> bool {
    authority == "localhost"
        || authority.starts_with('[')
        || is_ipv4(authority)
        || authority.contains('.')
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Returns true if a path segment is a dot-dot traversal, in literal or
/// percent-encoded forms (`%2e%2e`, `%2e.`, `.%2e`).
fn is_dotdot(seg: &str) -> bool {
    if seg == ".." {
        return true;
    }
    // Case-insensitive comparison after normalising %2e → .
    let lower = seg.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "%2e%2e" | "%2e." | ".%2e" | "%2e%2F" | "%2f"
    ) || {
        // Percent-decode the segment and check again
        let decoded = percent_decode(seg);
        decoded == ".."
    }
}

/// Minimal percent-decoder for the ASCII subset used in pap:// paths.
/// Only decodes %XX sequences; leaves everything else intact.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push((hi * 16 + lo) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Strip control characters from a path segment before embedding in an intent string.
fn sanitize_intent_path(path: &str) -> String {
    path.chars().filter(|c| !c.is_control()).collect()
}

fn special_to_intent(authority: &str, path: &str) -> String {
    let path = sanitize_intent_path(path.trim_start_matches('/'));
    match authority {
        "receipt" => {
            if path.is_empty() {
                "show receipts".into()
            } else {
                format!("show receipt {}", path)
            }
        }
        "canvas" => {
            let mut parts = path.splitn(2, '/');
            match (parts.next(), parts.next()) {
                (Some(cid), Some(bid)) if !cid.is_empty() => {
                    format!("show canvas {} block {}", cid, bid)
                }
                (Some(cid), _) if !cid.is_empty() => format!("show canvas {}", cid),
                _ => "show canvas".into(),
            }
        }
        "settings" => {
            if path.is_empty() {
                "open settings".into()
            } else {
                format!("open settings {}", path)
            }
        }
        _ => unreachable!("special_to_intent called with non-reserved authority"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty() -> HashMap<String, String> {
        HashMap::new()
    }

    fn catalog(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn special_receipt_principal() {
        let r =
            resolve_pap_uri("pap://receipt/RCP_abc123", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(
            r,
            ResolvedUri::LocalIntent("show receipt RCP_abc123".into())
        );
    }

    #[test]
    fn special_receipt_agent_is_blocked() {
        let err =
            resolve_pap_uri("pap://receipt/RCP_abc123", &empty(), LinkOrigin::Agent).unwrap_err();
        assert_eq!(err, PapUriError::Reserved);
    }

    #[test]
    fn special_canvas_agent_is_blocked() {
        let err = resolve_pap_uri("pap://canvas/cid/bid", &empty(), LinkOrigin::Agent).unwrap_err();
        assert_eq!(err, PapUriError::Reserved);
    }

    #[test]
    fn special_settings_principal() {
        let r = resolve_pap_uri("pap://settings/general", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("open settings general".into()));
    }

    #[test]
    fn special_canvas_with_block() {
        let r = resolve_pap_uri("pap://canvas/cid/blk", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(
            r,
            ResolvedUri::LocalIntent("show canvas cid block blk".into())
        );
    }

    #[test]
    fn did_key_passthrough() {
        let uri = "pap://did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Did(uri.into()));
    }

    #[test]
    fn catalog_rewrite() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri(
            "pap://arxiv/SearchAction?query=quantum%20computing",
            &cat,
            LinkOrigin::Principal,
        )
        .unwrap();
        assert_eq!(
            r,
            ResolvedUri::Did(
                "pap://did:key:z6MkTestKey/SearchAction?query=quantum%20computing".into()
            )
        );
    }

    #[test]
    fn catalog_miss_returns_not_found() {
        let err = resolve_pap_uri(
            "pap://unknown/SearchAction",
            &empty(),
            LinkOrigin::Principal,
        )
        .unwrap_err();
        assert_eq!(err, PapUriError::NotFound("unknown".into()));
    }

    #[test]
    fn registry_hostname_passthrough() {
        let uri = "pap://chrysalis.example.com/agents/arxiv/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Registry(uri.into()));
    }

    #[test]
    fn localhost_is_registry_host() {
        let uri = "pap://localhost/agents/dev/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Registry(uri.into()));
    }

    #[test]
    fn ipv4_is_registry_host() {
        let uri = "pap://192.168.1.1/agents/local/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::Registry(uri.into()));
    }

    #[test]
    fn recapture_https_deferred() {
        let err = resolve_pap_uri(
            "pap+https://api.example.com/agents/flights/BuyAction",
            &empty(),
            LinkOrigin::Principal,
        )
        .unwrap_err();
        assert_eq!(err, PapUriError::RecaptureDeferred);
    }

    #[test]
    fn recapture_wss_deferred() {
        let err = resolve_pap_uri(
            "pap+wss://stream.example.com/agents/feed/ListenAction",
            &empty(),
            LinkOrigin::Principal,
        )
        .unwrap_err();
        assert_eq!(err, PapUriError::RecaptureDeferred);
    }

    #[test]
    fn non_pap_uri_parse_error() {
        let err =
            resolve_pap_uri("https://example.com", &empty(), LinkOrigin::Principal).unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn empty_authority_parse_error() {
        let err =
            resolve_pap_uri("pap:///SearchAction", &empty(), LinkOrigin::Principal).unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn catalog_lookup_is_case_insensitive() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri("pap://ARXIV/SearchAction", &cat, LinkOrigin::Principal).unwrap();
        assert!(matches!(r, ResolvedUri::Did(_)));
    }

    #[test]
    fn special_canvas_without_block() {
        let r = resolve_pap_uri("pap://canvas/cid", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show canvas cid".into()));
    }

    #[test]
    fn reserved_words_not_catalog_matched() {
        // Even if catalog has "receipt", special authority check fires first
        let cat = catalog(&[("receipt", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri("pap://receipt/RCP_1", &cat, LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show receipt RCP_1".into()));
    }

    #[test]
    fn path_traversal_in_catalog_rewrite_is_rejected() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let err = resolve_pap_uri("pap://arxiv/../../etc/passwd", &cat, LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn percent_encoded_dotdot_traversal_is_rejected() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        // %2e%2e is a percent-encoded ".."
        let err = resolve_pap_uri("pap://arxiv/%2e%2e/etc/passwd", &cat, LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn mixed_encoded_dotdot_traversal_is_rejected() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        // %2e. is ".." with one dot encoded
        let err = resolve_pap_uri("pap://arxiv/%2e./etc/passwd", &cat, LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn control_chars_stripped_from_intent_path() {
        let r = resolve_pap_uri(
            "pap://receipt/RCP_1\nDelete%20all",
            &empty(),
            LinkOrigin::Principal,
        )
        .unwrap();
        // The newline should be stripped; remaining text is kept
        assert_eq!(
            r,
            ResolvedUri::LocalIntent("show receipt RCP_1Delete%20all".into())
        );
    }

    #[test]
    fn control_chars_stripped_from_catalog_rewrite_path() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri(
            "pap://arxiv/Action\x00injected",
            &cat,
            LinkOrigin::Principal,
        )
        .unwrap();
        // Null byte must be stripped from the rewritten DID URI
        assert_eq!(
            r,
            ResolvedUri::Did("pap://did:key:z6MkTestKey/Actioninjected".into())
        );
    }

    #[test]
    fn did_key_authority_is_case_insensitive() {
        let uri = "pap://DID:KEY:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK/SearchAction";
        let r = resolve_pap_uri(uri, &empty(), LinkOrigin::Principal).unwrap();
        // Uppercased DID:KEY: must be treated as a DID passthrough, not NotFound
        assert_eq!(r, ResolvedUri::Did(uri.into()));
    }
}
