//! Guards against SSRF by validating peer endpoint URLs.

use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};

/// Returns `Ok(())` if the URL is safe to connect to as a federation peer,
/// or `Err(reason)` if the URL should be rejected.
///
/// Rules:
/// - Scheme must be `https` (plain HTTP peers rejected)
/// - Hostname must not resolve to a loopback, private, link-local, or
///   broadcast IPv4 address, or loopback IPv6 address
/// - Hostname must not be a bare IP in a private range (fast path, pre-DNS)
pub fn assert_safe_peer_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url)
        .map_err(|e| format!("invalid peer URL: {e}"))?;

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
    // If DNS resolution fails, allow the URL through — the hostname may resolve
    // correctly at connection time (e.g. different resolver context). We only
    // block hostnames that positively resolve to a blocked range.
    let port = parsed.port().unwrap_or(443);
    if let Ok(addrs) = format!("{host}:{port}").to_socket_addrs() {
        for addr in addrs {
            if is_blocked_ip(addr.ip()) {
                return Err(format!(
                    "peer hostname '{host}' resolves to blocked IP {}",
                    addr.ip()
                ));
            }
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
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Carrier-Grade NAT range: 100.64.0.0/10
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requires external DNS to resolve `registry.example.com`.
    /// Marked `#[ignore]` because the test environment has no external DNS access.
    #[test]
    #[ignore]
    fn accepts_https_public_host() {
        assert!(assert_safe_peer_url("https://registry.example.com/").is_ok());
    }

    #[test]
    fn rejects_http_scheme() {
        assert!(assert_safe_peer_url("http://registry.example.com/").is_err());
    }

    #[test]
    fn rejects_loopback_ip() {
        assert!(assert_safe_peer_url("https://127.0.0.1:7890/").is_err());
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(assert_safe_peer_url("https://[::1]:7890/").is_err());
    }

    #[test]
    fn rejects_private_10_block() {
        assert!(assert_safe_peer_url("https://10.0.0.1/").is_err());
    }

    #[test]
    fn rejects_private_192_168() {
        assert!(assert_safe_peer_url("https://192.168.1.1/").is_err());
    }

    #[test]
    fn rejects_private_172_16() {
        assert!(assert_safe_peer_url("https://172.16.0.1/").is_err());
    }

    #[test]
    fn rejects_cgnat_100_64() {
        assert!(assert_safe_peer_url("https://100.64.0.1/").is_err());
    }

    #[test]
    fn rejects_link_local_169_254() {
        assert!(assert_safe_peer_url("https://169.254.0.1/").is_err());
    }

    #[test]
    fn rejects_invalid_url() {
        assert!(assert_safe_peer_url("not-a-url").is_err());
    }

    #[test]
    fn rejects_localhost_hostname() {
        assert!(assert_safe_peer_url("https://localhost/").is_err());
    }

    #[test]
    fn rejects_dot_local_hostname() {
        assert!(assert_safe_peer_url("https://registry.local/").is_err());
    }

    #[test]
    fn rejects_dot_internal_hostname() {
        assert!(assert_safe_peer_url("https://internal.corp.internal/").is_err());
    }
}
