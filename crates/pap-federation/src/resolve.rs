//! PAP URL parser — turns `pap://` and `pap+transport://` URLs into
//! host + port + transport binding.
//!
//! `pap://` is its own protocol with its own transport layer (TLS
//! secured, DID-rooted trust). Compound schemes declare an explicit
//! transport binding:
//!
//! - `pap://`       — native PAP transport (DID + fingerprint trust)
//! - `pap+https://` — PAP federation over HTTPS (browser-compatible)
//! - `pap+wss://`   — PAP federation over WebSocket Secure
//!
//! This module handles parsing only — trust establishment (TOFU
//! bootstrap, fingerprint pinning, CORS negotiation) lives in the caller.

use crate::error::FederationError;

/// Default port for PAP federation nodes.
pub const DEFAULT_PAP_PORT: u16 = 7890;

/// The transport binding for a PAP URL.
///
/// PAP is a protocol — how it reaches the wire is a separate concern.
/// Native transport implies DID + certificate-pinned TLS. Compound
/// schemes bind PAP to a standard transport (HTTPS, WSS) for
/// environments where native transport isn't available (e.g. browsers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PapTransport {
    /// `pap://` — native PAP transport with DID-rooted TLS trust.
    /// Not available from browsers (no mDNS/UDP, no cert pinning).
    Native,

    /// `pap+https://` — PAP federation carried over HTTPS.
    /// Browser-compatible. Requires CORS headers on the server.
    Https,

    /// `pap+wss://` — PAP federation carried over WebSocket Secure.
    /// Useful for full-duplex federation streams.
    Wss,
}

/// A parsed PAP URL with transport binding.
#[derive(Debug, Clone)]
pub struct PapUrl {
    pub host: String,
    pub port: u16,
    pub transport: PapTransport,
}

impl PapUrl {
    /// Parse a PAP URL.
    ///
    /// Accepts:
    /// - `pap://host:port`          — native transport
    /// - `pap+https://host:port`    — HTTPS binding
    /// - `pap+wss://host:port`      — WSS binding
    /// - `pap://host`               — native, default port 7890
    /// - Bare `host:port` or `host` — native, for convenience
    ///
    /// Rejects raw `http://`, `https://`, `ws://`, `wss://` — those
    /// aren't PAP. Use the compound scheme to declare the binding.
    pub fn parse(url: &str) -> Result<Self, FederationError> {
        let trimmed = url.trim();

        // Reject raw transport schemes — PAP is its own protocol.
        // Use pap+https:// or pap+wss:// to declare the binding.
        for scheme in &["http://", "https://", "ws://", "wss://"] {
            if trimmed.starts_with(scheme) {
                return Err(FederationError::InvalidUrl(format!(
                    "'{trimmed}' is not a PAP URL — use pap://, pap+https://, or pap+wss://"
                )));
            }
        }

        // Determine transport from scheme prefix
        let (transport, hostport) = if trimmed.starts_with("pap+https://") {
            (
                PapTransport::Https,
                trimmed.trim_start_matches("pap+https://"),
            )
        } else if trimmed.starts_with("pap+wss://") {
            (PapTransport::Wss, trimmed.trim_start_matches("pap+wss://"))
        } else if trimmed.starts_with("pap+") {
            // Reject unknown compound schemes
            return Err(FederationError::InvalidUrl(format!(
                "unknown PAP transport binding: '{trimmed}'"
            )));
        } else if trimmed.starts_with("pap://") {
            (PapTransport::Native, trimmed.trim_start_matches("pap://"))
        } else {
            // Bare host:port — treat as native
            (PapTransport::Native, trimmed)
        };

        let hostport = hostport.trim_end_matches('/');

        if hostport.is_empty() {
            return Err(FederationError::InvalidUrl("empty PAP URL".into()));
        }

        // Parse host:port
        let (host, port) = if let Some((h, port_str)) = hostport.rsplit_once(':') {
            if let Ok(p) = port_str.parse::<u16>() {
                (h.to_string(), p)
            } else {
                // No valid port after colon — treat whole thing as host
                (hostport.to_string(), DEFAULT_PAP_PORT)
            }
        } else {
            (hostport.to_string(), DEFAULT_PAP_PORT)
        };

        Ok(Self {
            host,
            port,
            transport,
        })
    }

    /// The connection endpoint URL for this PAP address.
    ///
    /// Returns the underlying transport URL:
    /// - Native → `https://host:port` (PAP uses TLS underneath)
    /// - Https  → `https://host:port`
    /// - Wss    → `wss://host:port`
    pub fn endpoint(&self) -> String {
        match self.transport {
            PapTransport::Native | PapTransport::Https => {
                format!("https://{}:{}", self.host, self.port)
            }
            PapTransport::Wss => {
                format!("wss://{}:{}", self.host, self.port)
            }
        }
    }

    /// The HTTPS endpoint URL for this PAP address.
    ///
    /// Always returns the HTTPS form regardless of transport binding.
    /// Useful for federation REST calls that always go over HTTPS.
    pub fn https_endpoint(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }

    /// Whether this URL uses a browser-compatible transport.
    pub fn is_browser_compatible(&self) -> bool {
        matches!(self.transport, PapTransport::Https | PapTransport::Wss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Native pap:// ---

    #[test]
    fn parse_full_pap_url() {
        let url = PapUrl::parse("pap://registry.example.com:7890").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, 7890);
        assert_eq!(url.transport, PapTransport::Native);
        assert_eq!(url.endpoint(), "https://registry.example.com:7890");
        assert_eq!(url.https_endpoint(), "https://registry.example.com:7890");
        assert!(!url.is_browser_compatible());
    }

    #[test]
    fn parse_pap_url_default_port() {
        let url = PapUrl::parse("pap://registry.example.com").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, DEFAULT_PAP_PORT);
        assert_eq!(url.transport, PapTransport::Native);
    }

    #[test]
    fn parse_bare_host() {
        let url = PapUrl::parse("192.168.1.100:9000").unwrap();
        assert_eq!(url.host, "192.168.1.100");
        assert_eq!(url.port, 9000);
        assert_eq!(url.transport, PapTransport::Native);
    }

    #[test]
    fn parse_bare_host_default_port() {
        let url = PapUrl::parse("registry.example.com").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, DEFAULT_PAP_PORT);
    }

    // --- Compound pap+https:// ---

    #[test]
    fn parse_pap_https() {
        let url = PapUrl::parse("pap+https://registry.example.com:443").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.transport, PapTransport::Https);
        assert_eq!(url.endpoint(), "https://registry.example.com:443");
        assert!(url.is_browser_compatible());
    }

    #[test]
    fn parse_pap_https_default_port() {
        let url = PapUrl::parse("pap+https://registry.example.com").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, DEFAULT_PAP_PORT);
        assert_eq!(url.transport, PapTransport::Https);
    }

    // --- Compound pap+wss:// ---

    #[test]
    fn parse_pap_wss() {
        let url = PapUrl::parse("pap+wss://stream.example.com:8443").unwrap();
        assert_eq!(url.host, "stream.example.com");
        assert_eq!(url.port, 8443);
        assert_eq!(url.transport, PapTransport::Wss);
        assert_eq!(url.endpoint(), "wss://stream.example.com:8443");
        assert!(url.is_browser_compatible());
    }

    // --- Rejections ---

    #[test]
    fn reject_raw_http() {
        let result = PapUrl::parse("http://example.com");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a PAP URL"));
    }

    #[test]
    fn reject_raw_https() {
        let result = PapUrl::parse("https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_raw_wss() {
        let result = PapUrl::parse("wss://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_unknown_compound_scheme() {
        let result = PapUrl::parse("pap+ftp://example.com");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unknown PAP transport binding"));
    }

    #[test]
    fn reject_empty_url() {
        let result = PapUrl::parse("pap://");
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_compound_url() {
        let result = PapUrl::parse("pap+https://");
        assert!(result.is_err());
    }

    #[test]
    fn strip_trailing_slash() {
        let url = PapUrl::parse("pap://example.com:7890/").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 7890);
    }

    #[test]
    fn strip_trailing_slash_compound() {
        let url = PapUrl::parse("pap+https://example.com:443/").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.transport, PapTransport::Https);
    }

    // --- Edge cases ---

    #[test]
    fn leading_trailing_whitespace_trimmed() {
        let url = PapUrl::parse("  pap://example.com:7890  ").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 7890);
    }

    #[test]
    fn compound_whitespace_trimmed() {
        let url = PapUrl::parse("  pap+https://example.com  ").unwrap();
        assert_eq!(url.transport, PapTransport::Https);
        assert_eq!(url.host, "example.com");
    }

    #[test]
    fn reject_raw_ws() {
        let result = PapUrl::parse("ws://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn pap_transport_equality() {
        assert_eq!(PapTransport::Native, PapTransport::Native);
        assert_eq!(PapTransport::Https, PapTransport::Https);
        assert_eq!(PapTransport::Wss, PapTransport::Wss);
        assert_ne!(PapTransport::Native, PapTransport::Https);
        assert_ne!(PapTransport::Https, PapTransport::Wss);
    }

    #[test]
    fn pap_transport_copy() {
        let t = PapTransport::Https;
        let t2 = t; // Copy
        assert_eq!(t, t2);
    }

    #[test]
    fn wss_https_endpoint_still_returns_https() {
        let url = PapUrl::parse("pap+wss://stream.example.com:8443").unwrap();
        // endpoint() should return wss://
        assert_eq!(url.endpoint(), "wss://stream.example.com:8443");
        // https_endpoint() always returns https://
        assert_eq!(url.https_endpoint(), "https://stream.example.com:8443");
    }

    #[test]
    fn native_not_browser_compatible() {
        let url = PapUrl::parse("pap://node.example.com").unwrap();
        assert!(!url.is_browser_compatible());
    }

    #[test]
    fn wss_is_browser_compatible() {
        let url = PapUrl::parse("pap+wss://node.example.com").unwrap();
        assert!(url.is_browser_compatible());
    }

    #[test]
    fn default_pap_port_value() {
        assert_eq!(DEFAULT_PAP_PORT, 7890);
    }
}
