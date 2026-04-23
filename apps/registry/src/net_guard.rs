//! Guards against SSRF by validating peer endpoint URLs.
//!
//! # Security Model
//!
//! This guard provides best-effort SSRF protection by checking URLs at
//! registration time. It blocks:
//! - Non-HTTPS schemes
//! - Private, loopback, link-local, and CGNAT IP ranges (IPv4 and IPv6)
//! - Well-known local hostnames (localhost, *.local, *.internal)
//! - Hostnames that resolve to blocked IP ranges at registration time
//!
//! # Known Limitations
//!
//! **DNS rebinding:** Hostname checks are performed at peer registration time.
//! Between registration and the next actual HTTP connection, an attacker with
//! DNS control could switch the record to an internal target. The TLS layer
//! (certificate pinning via `PinnedCertVerifier`) provides the primary
//! connection-time integrity guarantee for federation peers.
//!
//! **DNS failure:** Hostnames that fail DNS resolution at registration time
//! are rejected. Re-register after DNS is resolvable.

use std::net::{IpAddr, Ipv4Addr};

/// Returns `Ok(())` if the URL is safe to connect to as a federation peer,
/// or `Err(reason)` if the URL should be rejected.
///
/// Rules:
/// - Scheme must be `https` (plain HTTP peers rejected)
/// - Hostname must not resolve to a loopback, private, link-local, or
///   broadcast IPv4 address, or loopback/link-local/unique-local IPv6 address
/// - Hostname must not be a bare IP in a private range (fast path, pre-DNS)
/// - Hostnames that fail DNS resolution at registration time are rejected
pub async fn assert_safe_peer_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid peer URL: {e}"))?;

    if parsed.scheme() != "https" {
        return Err(format!(
            "peer endpoint scheme '{}' is not allowed; only https is permitted",
            parsed.scheme()
        ));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| "peer URL has no host".to_string())?;

    // Block well-known local hostnames without DNS lookup
    let lower = host.to_lowercase();
    if lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".internal") {
        return Err(format!("peer hostname '{host}' is in a blocked domain"));
    }

    // Fast path: reject bare IP addresses in private ranges without DNS lookup
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_blocked_ip(ip) {
            Err(format!("peer endpoint IP {ip} is in a blocked range"))
        } else {
            Ok(())
        };
    }

    // Resolve hostname and check each resulting address.
    // DNS failure is treated as a rejection — the hostname must have valid DNS
    // before it can be registered as a federation peer.
    let port = parsed.port().unwrap_or(443);
    match tokio::net::lookup_host(format!("{host}:{port}")).await {
        Ok(addrs) => {
            for addr in addrs {
                if is_blocked_ip(addr.ip()) {
                    return Err(format!(
                        "peer hostname '{}' resolves to blocked IP {}",
                        host,
                        addr.ip()
                    ));
                }
            }
        }
        Err(e) => {
            return Err(format!(
                "peer hostname '{}' could not be resolved; ensure the hostname has valid DNS \
                 before registering: {e}",
                host
            ));
        }
    }

    Ok(())
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || is_cgnat(v4)
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            // Unique-local: fc00::/7 (private ranges in IPv6)
            let segs = v6.segments();
            if (segs[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Link-local: fe80::/10
            if (segs[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // IPv4-mapped: ::ffff:0:0/96 — check the embedded IPv4 address
            if let Some(ipv4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(ipv4));
            }
            false
        }
    }
}

/// Carrier-Grade NAT range: 100.64.0.0/10 (octets[1] in [64..=127])
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requires external DNS to resolve `registry.example.com`.
    /// Marked `#[ignore]` because the test environment has no external DNS access.
    /// Run with `cargo test -- --ignored` in environments with real DNS.
    #[tokio::test]
    #[ignore]
    async fn accepts_https_public_host() {
        assert!(assert_safe_peer_url("https://registry.example.com/")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn rejects_http_scheme() {
        assert!(assert_safe_peer_url("http://registry.example.com/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_loopback_ip() {
        assert!(assert_safe_peer_url("https://127.0.0.1:7890/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_loopback() {
        assert!(assert_safe_peer_url("https://[::1]:7890/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_10_block() {
        assert!(assert_safe_peer_url("https://10.0.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_192_168() {
        assert!(assert_safe_peer_url("https://192.168.1.1/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_172_16() {
        assert!(assert_safe_peer_url("https://172.16.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_cgnat_100_64() {
        assert!(assert_safe_peer_url("https://100.64.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_link_local_169_254() {
        assert!(assert_safe_peer_url("https://169.254.0.1/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_invalid_url() {
        assert!(assert_safe_peer_url("not-a-url").await.is_err());
    }

    #[tokio::test]
    async fn rejects_localhost_hostname() {
        assert!(assert_safe_peer_url("https://localhost/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_dot_local_hostname() {
        assert!(assert_safe_peer_url("https://registry.local/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_dot_internal_hostname() {
        assert!(assert_safe_peer_url("https://internal.corp.internal/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_unique_local() {
        assert!(assert_safe_peer_url("https://[fd12:3456:789a:1::1]/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_link_local() {
        assert!(assert_safe_peer_url("https://[fe80::1]/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_ipv4_mapped_private() {
        // ::ffff:192.168.1.1 — IPv4-mapped private address
        assert!(assert_safe_peer_url("https://[::ffff:192.168.1.1]/")
            .await
            .is_err());
    }
}
