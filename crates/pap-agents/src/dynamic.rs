use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_agent_version() -> String {
    "0.1.0".into()
}

fn default_timeout_secs() -> u64 {
    5
}

fn default_response_jsonpath() -> String {
    "$".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAgentDef {
    pub agent_did: Option<String>,
    pub schema_version: u32,
    /// Semantic version of this agent (e.g. "1.0.0").
    /// Included in advertisement signature — setting overrides are pinned to this.
    #[serde(default = "default_agent_version")]
    pub version: String,
    pub name: String,
    pub provider: String,
    pub description: String,
    pub action: String,
    pub object_types: Vec<String>,
    pub requires_disclosure: Vec<String>,
    pub returns: Vec<String>,
    pub endpoint: Option<HttpEndpointConfig>,
    pub llm_instructions: String,
    pub subagents: Vec<String>,
    pub source: DynamicAgentSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_key_seed: Option<[u8; 32]>,
    pub published_to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_path: Option<String>,
    /// Configurable properties advertised as schema.org PropertyValueSpecification.
    /// Flows into AgentAdvertisement for federation — remote registries serve these.
    #[serde(default)]
    pub configurable_properties: Vec<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEndpointConfig {
    pub url_template: String,
    pub method: HttpMethod,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body_template: Option<String>,
    /// JSONPath for single-field extraction (fallback when `response_mapping` is empty).
    /// Defaults to `"$"` (full response body) when not specified.
    #[serde(default = "default_response_jsonpath")]
    pub response_jsonpath: String,
    pub response_schema_type: String,
    /// Schema.org property → JSONPath mapping for multi-field extraction.
    ///
    /// When present, the agent extracts each field from the API response and
    /// builds a proper schema.org object. When absent/empty (default), falls
    /// back to `response_jsonpath` single-value extraction.
    #[serde(default)]
    pub response_mapping: HashMap<String, String>,
    /// HTTP request timeout in seconds. Defaults to 5.
    /// Set higher (e.g. 30) for models with cold-start latency.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DynamicAgentSource {
    Catalog,
    UserCreated,
    Generated,
}

/// Validate that a URL is safe to use as an HTTP endpoint.
///
/// Returns `false` for any of:
/// - Non-https scheme
/// - `localhost` host
/// - URLs containing userinfo (`user:pass@host`) — RFC 3986 §3.2.1, including
///   percent-encoded variants such as `%40` (encoded `@`)
/// - IPv4 RFC 1918 ranges: 127.x, 10.x, 172.16–31.x, 192.168.x
/// - Link-local: 169.254.x
/// - Bare IPv4 or IPv6 address literals (any address, not just private ones)
/// - Decimal or hex integer IP notation (e.g. `2130706433`, `0x7f000001`)
///
/// Defense-in-depth: this check is enforced both at save time and at execution time
/// (see spec §4.1).
///
/// **Known limitation — DNS rebinding:** This function performs static string
/// validation and does not resolve hostnames. A name like `127.0.0.1.nip.io`
/// (which resolves to a private IP via DNS) will pass validation. Mitigate at
/// the network layer with egress firewall rules blocking RFC 1918 destinations.
///
/// **Known limitation — numeric IP notation:** Decimal and hex integer formats
/// are blocked on a best-effort basis (see check below), but full DNS resolution
/// is not performed. Rely on network-layer egress filtering as an additional
/// defence.
pub fn is_safe_url(url: &str) -> bool {
    // Must be https://
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false,
    };

    // Parse via the `url` crate so that percent-encoding is decoded before any
    // checks.  This prevents `%40`-encoded `@` from bypassing the userinfo check
    // (Fix 1 — review finding: critical).
    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        Err(_) => return false,
    };

    // Reject URLs with userinfo (user:pass@host) — these can bypass host checks
    // and have no legitimate use in agent endpoint URLs.  Checking via the parsed
    // representation catches both literal `@` and the `%40` percent-encoded form.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }

    // Extract authority (everything before the first '/', '?', '#', or end of string)
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_ascii_lowercase();

    // Remove port if present
    let host = match authority.rfind(':') {
        Some(i) => authority[..i].to_string(),
        None => authority,
    };

    // Reject empty host
    if host.is_empty() {
        return false;
    }

    // Reject localhost
    if host == "localhost" {
        return false;
    }

    // Reject bare IPv6 literals (wrapped in brackets: [::1], [fe80::1], etc.)
    if host.starts_with('[') {
        return false;
    }

    // Block decimal and hex integer IP notation (e.g. 2130706433 → 127.0.0.1,
    // 0x7f000001 → 127.0.0.1).  This is best-effort static analysis — full DNS
    // resolution is not performed here (see known limitation in doc-comment above).
    // Fix 2 — review finding: informational.
    if host.starts_with("0x") || host.parse::<u32>().is_ok() {
        return false;
    }

    // Reject RFC 1918, loopback, link-local, and any other special-purpose IPv4 ranges.
    // Also rejects bare public IPv4 literals — agents must use hostnames.
    let segments: Vec<&str> = host.split('.').collect();
    if segments.len() == 4 {
        if let (Ok(a), Ok(b), Ok(_c), Ok(_d)) = (
            segments[0].parse::<u16>(),
            segments[1].parse::<u16>(),
            segments[2].parse::<u16>(),
            segments[3].parse::<u16>(),
        ) {
            // All four segments are numeric — this is a bare IPv4 literal. Reject all of them.
            // This covers loopback (127.x), RFC 1918 (10.x, 172.16-31.x, 192.168.x),
            // link-local (169.254.x), and any public IP literal.
            let _ = (a, b, _c, _d);
            return false;
        }
    }

    // Fallback: attempt Ipv4Addr parse for non-standard dotted forms (e.g. "010.0.0.1")
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }

    true
}

/// Validate that a URL is acceptable for a **user-configured local LLM** endpoint.
///
/// This is a superset of [`is_safe_url`] that additionally permits plain-HTTP
/// connections to the loopback interface (`localhost` and `127.0.0.1`).
/// Ollama and other local inference servers run on `http://localhost` by default
/// and cannot be switched to HTTPS without substantial user effort.
///
/// **Scope:** Use ONLY for the Ollama / local-LLM endpoint that the user
/// configures in Papillon's settings.  All other outbound endpoints (catalog
/// agents, dynamic agents, registry federation) must continue to use
/// [`is_safe_url`] which requires HTTPS + a public hostname.
///
/// # Security note
/// Allowing `http://localhost` is safe because the destination is the same
/// machine as the app.  Requests never leave the device, so there is no
/// plaintext leakage risk.  The RFC 1918 / link-local blocks remain in effect —
/// only the two loopback identifiers are whitelisted.
pub fn is_local_llm_url(url: &str) -> bool {
    // HTTPS public-hostname URLs are always accepted.
    if is_safe_url(url) {
        return true;
    }
    // Additionally accept http://localhost[:<port>][/path] and
    // http://127.0.0.1[:<port>][/path].
    let rest = match url.strip_prefix("http://") {
        Some(r) => r,
        None => return false,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = match authority.rfind(':') {
        Some(i) => &authority[..i],
        None => authority,
    };
    host == "localhost" || host == "127.0.0.1"
}

impl DynamicAgentDef {
    /// Return the top-level category of this agent derived from its `catalog_path`.
    ///
    /// The category is the first path component before the first `/` in
    /// `catalog_path` (e.g. `"search"` from `"search/duckduckgo.toml"`).
    /// Returns `"general"` when `catalog_path` is `None`, empty, or has no
    /// path separator.
    pub fn category(&self) -> &str {
        self.catalog_path
            .as_deref()
            .and_then(|p| p.split('/').next())
            .filter(|s| !s.is_empty())
            .unwrap_or("general")
    }

    /// Build a signed [`pap_marketplace::AgentAdvertisement`] using a deterministic
    /// Ed25519 keypair derived from this agent's name via SHA-256.
    ///
    /// The same name always produces the same operator DID and content hash, making
    /// this suitable for idempotent catalog installs and first-boot registry seeding.
    pub fn to_signed_advertisement(&self) -> Result<pap_marketplace::AgentAdvertisement, String> {
        use ed25519_dalek::SigningKey;
        use pap_did::public_key_to_did;
        use sha2::{Digest, Sha256};

        let seed_bytes: [u8; 32] = Sha256::digest(self.name.as_bytes()).into();
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let operator_did = public_key_to_did(&signing_key.verifying_key());

        let mut ad = pap_marketplace::AgentAdvertisement::new(
            &self.name,
            &self.provider,
            &operator_did,
            vec![self.action.clone()],
            self.object_types.clone(),
            self.requires_disclosure.clone(),
            self.returns.clone(),
        );
        ad.ttl_min = 3600;
        if !self.version.is_empty() {
            ad = ad.with_version(&self.version);
        }
        if !self.configurable_properties.is_empty() {
            ad = ad.with_configurable_properties(self.configurable_properties.clone());
        }

        ad.sign(&signing_key)
            .map_err(|e| format!("Failed to sign '{}': {e}", self.name))?;
        Ok(ad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_public_host_is_safe() {
        assert!(is_safe_url("https://api.example.com/v1?q=rust"));
        assert!(is_safe_url("https://world.openfoodfacts.org/cgi/search.pl"));
        assert!(is_safe_url("https://api.duckduckgo.com/?q=foo&format=json"));
    }

    #[test]
    fn http_scheme_rejected() {
        assert!(!is_safe_url("http://api.example.com/v1"));
    }

    #[test]
    fn ftp_scheme_rejected() {
        assert!(!is_safe_url("ftp://files.example.com/data"));
    }

    #[test]
    fn no_scheme_rejected() {
        assert!(!is_safe_url("api.example.com/v1"));
    }

    #[test]
    fn localhost_rejected() {
        assert!(!is_safe_url("https://localhost/api"));
        assert!(!is_safe_url("https://localhost:8080/api"));
    }

    #[test]
    fn loopback_ipv4_rejected() {
        assert!(!is_safe_url("https://127.0.0.1/api"));
        assert!(!is_safe_url("https://127.0.0.1:8080/api"));
        assert!(!is_safe_url("https://127.1.2.3/api"));
    }

    #[test]
    fn rfc1918_10_block_rejected() {
        assert!(!is_safe_url("https://10.0.0.1/api"));
        assert!(!is_safe_url("https://10.255.255.255/api"));
    }

    #[test]
    fn rfc1918_172_block_rejected() {
        assert!(!is_safe_url("https://172.16.0.1/api"));
        assert!(!is_safe_url("https://172.20.0.1/api"));
        assert!(!is_safe_url("https://172.31.255.255/api"));
    }

    #[test]
    fn rfc1918_172_outside_block_allowed() {
        // Bare IPv4 literals are rejected regardless of range (all IPv4 literals blocked).
        // These addresses are outside the RFC 1918 172.16-31 range but still rejected
        // because all bare IPv4 literals are disallowed — agents must use hostnames.
        assert!(!is_safe_url("https://172.15.0.1/api"));
        assert!(!is_safe_url("https://172.32.0.1/api"));
    }

    #[test]
    fn rfc1918_192_168_rejected() {
        assert!(!is_safe_url("https://192.168.1.1/api"));
        assert!(!is_safe_url("https://192.168.0.1:443/api"));
    }

    #[test]
    fn link_local_169_254_rejected() {
        assert!(!is_safe_url("https://169.254.0.1/api"));
        assert!(!is_safe_url("https://169.254.169.254/latest/meta-data/"));
    }

    #[test]
    fn ipv6_literal_rejected() {
        assert!(!is_safe_url("https://[::1]/api"));
        assert!(!is_safe_url("https://[fe80::1]/api"));
        assert!(!is_safe_url("https://[2001:db8::1]/api"));
    }

    #[test]
    fn bare_ipv4_public_rejected() {
        assert!(!is_safe_url("https://1.1.1.1/dns-query"));
        assert!(!is_safe_url("https://8.8.8.8/"));
    }

    // ── ISS-842 hardening tests ──────────────────────────────────────

    #[test]
    fn userinfo_bypass_rejected() {
        // CVE-pattern: userinfo before private IP bypasses naive host extraction
        assert!(!is_safe_url("https://user:pass@127.0.0.1/api"));
        assert!(!is_safe_url("https://x@169.254.169.254/latest/meta-data/"));
        assert!(!is_safe_url("https://admin:secret@10.0.0.1/"));
        assert!(!is_safe_url("https://a@192.168.1.1:443/api"));
        // Userinfo with public host is also rejected — no legitimate use case
        assert!(!is_safe_url("https://admin:password@api.example.com/v1"));
    }

    #[test]
    fn zero_addr_rejected() {
        assert!(!is_safe_url("https://0.0.0.0/api"));
        assert!(!is_safe_url("https://0.0.0.0:443/"));
    }

    #[test]
    fn file_scheme_rejected() {
        assert!(!is_safe_url("file:///etc/passwd"));
        assert!(!is_safe_url("file://localhost/etc/hosts"));
    }

    #[test]
    fn data_scheme_rejected() {
        assert!(!is_safe_url("data:text/html,<h1>hi</h1>"));
    }

    #[test]
    fn javascript_scheme_rejected() {
        assert!(!is_safe_url("javascript:alert(1)"));
    }

    #[test]
    fn empty_string_rejected() {
        assert!(!is_safe_url(""));
    }

    #[test]
    fn malformed_url_rejected() {
        assert!(!is_safe_url("not-a-url"));
        assert!(!is_safe_url("://missing-scheme"));
        assert!(!is_safe_url("https://"));
    }

    #[test]
    fn ipv6_unique_local_rejected() {
        // fc00::/7 — IPv6 unique local addresses (bracket notation)
        assert!(!is_safe_url("https://[fd00::1]/api"));
        assert!(!is_safe_url("https://[fc00::1]/api"));
    }

    #[test]
    fn template_variable_not_in_url_is_safe() {
        // Templates with {query} in query-string position are fine
        assert!(is_safe_url(
            "https://api.example.com/search?q={query}&format=json"
        ));
        assert!(is_safe_url(
            "https://world.openfoodfacts.org/cgi/search.pl?search_terms={query}&json=1"
        ));
    }

    #[test]
    fn octal_ipv4_rejected() {
        // Non-standard dotted forms caught by Ipv4Addr::parse fallback
        assert!(!is_safe_url("https://0177.0.0.1/api"));
    }

    #[test]
    fn percent_encoded_at_sign_userinfo_rejected() {
        // %40 is the percent-encoding for '@'.  A naive raw-string check for '@'
        // would miss this bypass (Fix 1 — critical review finding).
        assert!(!is_safe_url("https://user%40host@127.0.0.1/api"));
        assert!(!is_safe_url(
            "https://admin%40evil%3Apass@api.example.com/v1"
        ));
        // Plain encoded username without password should also be rejected
        assert!(!is_safe_url("https://user%40name@api.example.com/path"));
    }

    #[test]
    fn decimal_integer_ip_rejected() {
        // 2130706433 == 0x7f000001 == 127.0.0.1 (loopback)
        assert!(!is_safe_url("https://2130706433/api"));
        // 167772161 == 0x0a000001 == 10.0.0.1 (RFC 1918)
        assert!(!is_safe_url("https://167772161/api"));
    }

    #[test]
    fn hex_integer_ip_rejected() {
        // 0x7f000001 == 127.0.0.1 (loopback)
        assert!(!is_safe_url("https://0x7f000001/api"));
        // 0xc0a80101 == 192.168.1.1 (RFC 1918)
        assert!(!is_safe_url("https://0xc0a80101/api"));
    }

    #[test]
    fn dynamic_agent_def_serializes_and_deserializes() {
        let def = DynamicAgentDef {
            agent_did: Some("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
            schema_version: 1,
            version: "0.1.0".into(),
            name: "Open Food Facts".to_string(),
            provider: "Open Food Facts".to_string(),
            description: "Look up nutritional data for food products".to_string(),
            action: "schema:SearchAction".to_string(),
            object_types: vec!["schema:FoodEstablishment".to_string()],
            requires_disclosure: vec![],
            returns: vec!["schema:NutritionInformation".to_string()],
            endpoint: Some(HttpEndpointConfig {
                url_template:
                    "https://world.openfoodfacts.org/cgi/search.pl?search_terms={query}&json=1"
                        .to_string(),
                method: HttpMethod::Get,
                headers: HashMap::new(),
                body_template: None,
                response_jsonpath: "$.products[0]".to_string(),
                response_schema_type: "schema:NutritionInformation".to_string(),
                response_mapping: HashMap::new(),
                timeout_secs: 5,
            }),
            llm_instructions: "You are a nutrition lookup assistant.".to_string(),
            subagents: vec![],
            source: DynamicAgentSource::Catalog,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: Some("food/open_food_facts.toml".to_string()),
            configurable_properties: vec![],
            created_at: "2026-04-01T00:00:00Z".to_string(),
            updated_at: "2026-04-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&def).unwrap();
        let back: DynamicAgentDef = serde_json::from_str(&json).unwrap();

        assert_eq!(back.name, def.name);
        assert_eq!(back.schema_version, 1);
        assert_eq!(back.source, DynamicAgentSource::Catalog);
        assert_eq!(back.action, "schema:SearchAction");
        assert!(back.operator_key_seed.is_none());
        assert_eq!(
            back.catalog_path,
            Some("food/open_food_facts.toml".to_string())
        );
    }

    #[test]
    fn operator_key_seed_absent_from_json_when_none() {
        let def = DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            version: "0.1.0".into(),
            name: "Test".to_string(),
            provider: "Test".to_string(),
            description: "test".to_string(),
            action: "schema:SearchAction".to_string(),
            object_types: vec![],
            requires_disclosure: vec![],
            returns: vec![],
            endpoint: None,
            llm_instructions: String::new(),
            subagents: vec![],
            source: DynamicAgentSource::UserCreated,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: None,
            configurable_properties: vec![],
            created_at: "2026-04-01T00:00:00Z".to_string(),
            updated_at: "2026-04-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&def).unwrap();
        assert!(!json.contains("operator_key_seed"));
        assert!(!json.contains("catalog_path"));
    }

    #[test]
    fn http_method_serializes_as_variant_name() {
        let get = serde_json::to_string(&HttpMethod::Get).unwrap();
        let post = serde_json::to_string(&HttpMethod::Post).unwrap();
        assert_eq!(get, "\"Get\"");
        assert_eq!(post, "\"Post\"");
    }

    #[test]
    fn dynamic_agent_source_variants_round_trip() {
        for src in [
            DynamicAgentSource::Catalog,
            DynamicAgentSource::UserCreated,
            DynamicAgentSource::Generated,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let back: DynamicAgentSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, back);
        }
    }

    // ── category() tests ───────────────────────────────────────────────────────

    fn minimal_def(catalog_path: Option<&str>) -> DynamicAgentDef {
        DynamicAgentDef {
            agent_did: None,
            schema_version: 1,
            version: "0.1.0".into(),
            name: "Test".into(),
            provider: "Test".into(),
            description: "test".into(),
            action: "schema:SearchAction".into(),
            object_types: vec![],
            requires_disclosure: vec![],
            returns: vec![],
            endpoint: None,
            llm_instructions: String::new(),
            subagents: vec![],
            source: DynamicAgentSource::Catalog,
            operator_key_seed: None,
            published_to: vec![],
            catalog_path: catalog_path.map(ToOwned::to_owned),
            configurable_properties: vec![],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn category_from_search_path() {
        let def = minimal_def(Some("search/duckduckgo.toml"));
        assert_eq!(def.category(), "search");
    }

    #[test]
    fn category_from_arts_path() {
        let def = minimal_def(Some("arts/music_search.toml"));
        assert_eq!(def.category(), "arts");
    }

    #[test]
    fn category_none_catalog_path_returns_general() {
        let def = minimal_def(None);
        assert_eq!(def.category(), "general");
    }

    #[test]
    fn category_user_created_none_returns_general() {
        let mut def = minimal_def(None);
        def.source = DynamicAgentSource::UserCreated;
        assert_eq!(def.category(), "general");
    }

    // ── is_local_llm_url tests ─────────────────────────────────────────────────

    #[test]
    fn local_llm_localhost_with_port_accepted() {
        assert!(is_local_llm_url("http://localhost:11434"));
        assert!(is_local_llm_url("http://localhost:11434/api/chat"));
        assert!(is_local_llm_url(
            "http://localhost:8080/v1/chat/completions"
        ));
    }

    #[test]
    fn local_llm_loopback_ipv4_accepted() {
        assert!(is_local_llm_url("http://127.0.0.1:11434"));
        assert!(is_local_llm_url("http://127.0.0.1:11434/api/generate"));
    }

    #[test]
    fn local_llm_https_public_still_accepted() {
        assert!(is_local_llm_url(
            "https://api.openai.com/v1/chat/completions"
        ));
        assert!(is_local_llm_url("https://llm.example.com/v1"));
    }

    #[test]
    fn local_llm_rejects_rfc1918() {
        assert!(!is_local_llm_url("http://192.168.1.100:11434"));
        assert!(!is_local_llm_url("http://10.0.0.1:11434"));
        assert!(!is_local_llm_url("http://172.16.0.1:11434"));
    }

    #[test]
    fn local_llm_rejects_http_public() {
        assert!(!is_local_llm_url("http://example.com/api"));
        assert!(!is_local_llm_url("http://api.openai.com/v1"));
    }

    #[test]
    fn local_llm_rejects_no_scheme() {
        assert!(!is_local_llm_url("localhost:11434"));
        assert!(!is_local_llm_url("127.0.0.1:11434"));
    }
}
