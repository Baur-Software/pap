//! PAP URL parser — turns `pap://` URLs into host + port.
//!
//! `pap://` is not an alias for HTTPS. It's a protocol scheme that
//! implies trust verification. This module handles parsing only —
//! trust establishment (TOFU bootstrap, fingerprint pinning, and
//! eventually DNS-based resolution) lives in the caller.

use crate::error::FederationError;

/// Default port for PAP federation nodes.
pub const DEFAULT_PAP_PORT: u16 = 7890;

/// A parsed `pap://` URL.
#[derive(Debug, Clone)]
pub struct PapUrl {
    pub host: String,
    pub port: u16,
}

impl PapUrl {
    /// Parse a `pap://` URL.
    ///
    /// Accepts:
    /// - `pap://host:port`
    /// - `pap://host` (uses default port 7890)
    /// - Bare `host:port` or `host` (for convenience)
    ///
    /// Rejects `http://` and `https://` — those aren't PAP.
    pub fn parse(url: &str) -> Result<Self, FederationError> {
        let trimmed = url.trim();

        // Reject non-PAP schemes explicitly
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            return Err(FederationError::InvalidUrl(format!(
                "'{trimmed}' is not a pap:// URL — PAP is its own protocol, not HTTP"
            )));
        }

        // Strip pap:// prefix if present, then trailing slashes
        let hostport = trimmed.trim_start_matches("pap://").trim_end_matches('/');

        if hostport.is_empty() {
            return Err(FederationError::InvalidUrl("empty pap:// URL".into()));
        }

        // Parse host:port
        if let Some((host, port_str)) = hostport.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                Ok(Self {
                    host: host.to_string(),
                    port,
                })
            } else {
                // No valid port after colon — treat whole thing as host
                Ok(Self {
                    host: hostport.to_string(),
                    port: DEFAULT_PAP_PORT,
                })
            }
        } else {
            Ok(Self {
                host: hostport.to_string(),
                port: DEFAULT_PAP_PORT,
            })
        }
    }

    /// The HTTPS endpoint URL for this PAP address.
    ///
    /// PAP uses TLS underneath — but the trust model is DID + fingerprint
    /// pinning, not CA certificates.
    pub fn https_endpoint(&self) -> String {
        format!("https://{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_pap_url() {
        let url = PapUrl::parse("pap://registry.example.com:7890").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, 7890);
        assert_eq!(url.https_endpoint(), "https://registry.example.com:7890");
    }

    #[test]
    fn parse_pap_url_default_port() {
        let url = PapUrl::parse("pap://registry.example.com").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, DEFAULT_PAP_PORT);
    }

    #[test]
    fn parse_bare_host() {
        let url = PapUrl::parse("192.168.1.100:9000").unwrap();
        assert_eq!(url.host, "192.168.1.100");
        assert_eq!(url.port, 9000);
    }

    #[test]
    fn parse_bare_host_default_port() {
        let url = PapUrl::parse("registry.example.com").unwrap();
        assert_eq!(url.host, "registry.example.com");
        assert_eq!(url.port, DEFAULT_PAP_PORT);
    }

    #[test]
    fn reject_http_url() {
        let result = PapUrl::parse("http://example.com");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not a pap:// URL"));
    }

    #[test]
    fn reject_https_url() {
        let result = PapUrl::parse("https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn reject_empty_url() {
        let result = PapUrl::parse("pap://");
        assert!(result.is_err());
    }

    #[test]
    fn strip_trailing_slash() {
        let url = PapUrl::parse("pap://example.com:7890/").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 7890);
    }
}
