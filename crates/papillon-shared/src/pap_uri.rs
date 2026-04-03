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
        return Ok(ResolvedUri::LocalIntent(special_to_intent(&authority_lower, path)));
    }

    // Step 1: did:key: authority
    if authority.starts_with("did:key:") {
        return Ok(ResolvedUri::Did(uri.to_string()));
    }

    // Step 3: hostname / localhost / IPv4 → registry
    if is_registry_host(authority) {
        return Ok(ResolvedUri::Registry(uri.to_string()));
    }

    // Step 2: catalog name
    if let Some(did) = catalog.get(authority_lower.as_str()) {
        let rewritten = format!("pap://{}{}", did, path);
        return Ok(ResolvedUri::Did(rewritten));
    }

    Err(PapUriError::NotFound(authority_lower))
}

fn is_registry_host(authority: &str) -> bool {
    authority == "localhost"
        || authority.starts_with('[')
        || authority.contains('.')
        || is_ipv4(authority)
}

fn is_ipv4(s: &str) -> bool {
    let count = s.split('.').count();
    count == 4 && s.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn special_to_intent(authority: &str, path: &str) -> String {
    let path = path.trim_start_matches('/');
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
        other => format!("open {}", other),
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
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn special_receipt_principal() {
        let r = resolve_pap_uri("pap://receipt/RCP_abc123", &empty(), LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show receipt RCP_abc123".into()));
    }

    #[test]
    fn special_receipt_agent_is_blocked() {
        let err = resolve_pap_uri("pap://receipt/RCP_abc123", &empty(), LinkOrigin::Agent).unwrap_err();
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
        assert_eq!(r, ResolvedUri::LocalIntent("show canvas cid block blk".into()));
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
            ResolvedUri::Did("pap://did:key:z6MkTestKey/SearchAction?query=quantum%20computing".into())
        );
    }

    #[test]
    fn catalog_miss_returns_not_found() {
        let err = resolve_pap_uri("pap://unknown/SearchAction", &empty(), LinkOrigin::Principal)
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
        let err = resolve_pap_uri("https://example.com", &empty(), LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn empty_authority_parse_error() {
        let err = resolve_pap_uri("pap:///SearchAction", &empty(), LinkOrigin::Principal)
            .unwrap_err();
        assert!(matches!(err, PapUriError::ParseError(_)));
    }

    #[test]
    fn catalog_lookup_is_case_insensitive() {
        let cat = catalog(&[("arxiv", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri("pap://ARXIV/SearchAction", &cat, LinkOrigin::Principal).unwrap();
        assert!(matches!(r, ResolvedUri::Did(_)));
    }

    #[test]
    fn reserved_words_not_catalog_matched() {
        // Even if catalog has "receipt", special authority check fires first
        let cat = catalog(&[("receipt", "did:key:z6MkTestKey")]);
        let r = resolve_pap_uri("pap://receipt/RCP_1", &cat, LinkOrigin::Principal).unwrap();
        assert_eq!(r, ResolvedUri::LocalIntent("show receipt RCP_1".into()));
    }
}
