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

    // ── Edge cases: scheme ────────────────────────────────────────────────────

    #[tokio::test]
    async fn rejects_ftp_scheme() {
        assert!(assert_safe_peer_url("ftp://93.184.216.34/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_file_scheme() {
        assert!(assert_safe_peer_url("file:///etc/passwd").await.is_err());
    }

    #[tokio::test]
    async fn rejects_empty_string() {
        assert!(assert_safe_peer_url("").await.is_err());
    }

    #[tokio::test]
    async fn rejects_no_host_url() {
        // data: URL has no host
        assert!(assert_safe_peer_url("data:text/plain,hello").await.is_err());
    }

    // ── Edge cases: IPv4 boundary addresses ───────────────────────────────────

    #[tokio::test]
    async fn rejects_loopback_127_0_0_2() {
        // 127.0.0.2 is still in the loopback range 127.0.0.0/8
        assert!(assert_safe_peer_url("https://127.0.0.2/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_loopback_127_255_255_255() {
        assert!(assert_safe_peer_url("https://127.255.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_unspecified_ipv4() {
        // 0.0.0.0 — unspecified address
        assert!(assert_safe_peer_url("https://0.0.0.0/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_broadcast_255_255_255_255() {
        assert!(assert_safe_peer_url("https://255.255.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_private_10_boundary_start() {
        assert!(assert_safe_peer_url("https://10.0.0.0/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_10_boundary_end() {
        assert!(assert_safe_peer_url("https://10.255.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_just_outside_private_10_block() {
        // 9.255.255.255 and 11.0.0.0 are public
        assert!(assert_safe_peer_url("https://11.0.0.0/").await.is_ok());
    }

    #[tokio::test]
    async fn rejects_private_172_16_boundary_start() {
        assert!(assert_safe_peer_url("https://172.16.0.0/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_172_31_boundary_end() {
        assert!(assert_safe_peer_url("https://172.31.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_just_outside_172_block_lower() {
        // 172.15.255.255 is public (below 172.16.0.0/12)
        assert!(assert_safe_peer_url("https://172.15.0.1/").await.is_ok());
    }

    #[tokio::test]
    async fn accepts_just_outside_172_block_upper() {
        // 172.32.0.0 is public (above 172.31.255.255)
        assert!(assert_safe_peer_url("https://172.32.0.0/").await.is_ok());
    }

    #[tokio::test]
    async fn rejects_private_192_168_boundary_start() {
        assert!(assert_safe_peer_url("https://192.168.0.0/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_private_192_168_boundary_end() {
        assert!(assert_safe_peer_url("https://192.168.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_just_outside_192_168_block() {
        // 192.169.0.0 is public (above 192.168.255.255)
        assert!(assert_safe_peer_url("https://192.169.0.0/").await.is_ok());
    }

    #[tokio::test]
    async fn rejects_cgnat_start_boundary() {
        // 100.64.0.0 is the first CGNAT address
        assert!(assert_safe_peer_url("https://100.64.0.0/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_cgnat_end_boundary() {
        // 100.127.255.255 is the last CGNAT address
        assert!(assert_safe_peer_url("https://100.127.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_just_below_cgnat() {
        // 100.63.255.255 is public (below 100.64.0.0/10)
        assert!(assert_safe_peer_url("https://100.63.255.255/")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn accepts_just_above_cgnat() {
        // 100.128.0.0 is public (above 100.127.255.255)
        assert!(assert_safe_peer_url("https://100.128.0.0/").await.is_ok());
    }

    #[tokio::test]
    async fn rejects_link_local_boundary_start() {
        // 169.254.0.0 is the first link-local address
        assert!(assert_safe_peer_url("https://169.254.0.0/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_link_local_boundary_end() {
        // 169.254.255.255 is the last link-local address
        assert!(assert_safe_peer_url("https://169.254.255.255/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_just_above_link_local() {
        // 169.255.0.0 is public
        assert!(assert_safe_peer_url("https://169.255.0.0/").await.is_ok());
    }

    // ── Edge cases: IPv6 boundary addresses ───────────────────────────────────

    #[tokio::test]
    async fn rejects_ipv6_unspecified() {
        // :: (all zeros) is unspecified
        assert!(assert_safe_peer_url("https://[::]/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_unique_local_fc00_start() {
        // fc00:: is the start of unique-local fc00::/7
        assert!(assert_safe_peer_url("https://[fc00::]/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_unique_local_fd_range() {
        // fdff:ffff::/32 is within the unique-local range
        assert!(assert_safe_peer_url("https://[fdff:ffff::1]/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_ipv6_just_outside_unique_local() {
        // fe00:: is just above the unique-local range (fc00::/7 ends at fdff:...)
        // fe00:: is actually in the reserved range but NOT unique-local or link-local
        // it's blocked by neither fc00::/7 (bit pattern 1111 1100 - 1111 1101)
        // nor fe80::/10. fe00:: has first octet 0xfe00, so:
        //   unique-local: (0xfe00 & 0xfe00) == 0xfc00? -> 0xfe00 & 0xfe00 = 0xfe00 != 0xfc00 -> no
        //   link-local:   (0xfe00 & 0xffc0) == 0xfe80? -> 0xfe00 & 0xffc0 = 0xfe00 != 0xfe80 -> no
        // So fe00:: is accepted (it's reserved/unassigned but not private)
        assert!(assert_safe_peer_url("https://[fe00::1]/").await.is_ok());
    }

    #[tokio::test]
    async fn rejects_ipv6_link_local_start() {
        // fe80:: is the start of link-local fe80::/10
        assert!(assert_safe_peer_url("https://[fe80::]/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_ipv6_link_local_end() {
        // febf:ffff:... is the last address in fe80::/10
        assert!(
            assert_safe_peer_url("https://[febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff]/")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_ipv4_mapped_loopback() {
        // ::ffff:127.0.0.1 — IPv4-mapped loopback
        assert!(assert_safe_peer_url("https://[::ffff:127.0.0.1]/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_ipv4_mapped_unspecified() {
        // ::ffff:0.0.0.0 — IPv4-mapped unspecified
        assert!(assert_safe_peer_url("https://[::ffff:0.0.0.0]/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_ipv4_mapped_10_block() {
        // ::ffff:10.0.0.1 — IPv4-mapped private 10.x.x.x
        assert!(assert_safe_peer_url("https://[::ffff:10.0.0.1]/")
            .await
            .is_err());
    }

    // ── Edge cases: hostname blocking ─────────────────────────────────────────

    #[tokio::test]
    async fn rejects_localhost_uppercase() {
        assert!(assert_safe_peer_url("https://LOCALHOST/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_localhost_mixed_case() {
        assert!(assert_safe_peer_url("https://LocalHost/").await.is_err());
    }

    #[tokio::test]
    async fn rejects_subdomain_of_local() {
        assert!(assert_safe_peer_url("https://foo.bar.local/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_dot_internal_uppercase() {
        assert!(assert_safe_peer_url("https://REGISTRY.INTERNAL/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_hostname_with_internal_substring_not_suffix() {
        // "internal" as a substring should NOT block (only the .internal suffix does)
        // This hostname will fail DNS, which is the expected rejection — but the
        // rejection reason must be DNS, not hostname blocking.
        let err = assert_safe_peer_url("https://internal-registry.example.com/")
            .await
            .unwrap_err();
        assert!(
            err.contains("could not be resolved") || err.contains("DNS"),
            "expected DNS failure, got: {err}"
        );
    }

    // ── Edge cases: URL structure ─────────────────────────────────────────────

    #[tokio::test]
    async fn accepts_https_with_explicit_port_443() {
        // Public IP with explicit port 443 — should be treated same as default
        assert!(assert_safe_peer_url("https://93.184.216.34:443/")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn accepts_https_with_non_standard_port() {
        // Non-standard port on a public IP is fine
        assert!(assert_safe_peer_url("https://93.184.216.34:8443/")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn rejects_private_ip_with_explicit_port() {
        // Port number doesn't exempt a private IP
        assert!(assert_safe_peer_url("https://192.168.1.1:8443/")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn accepts_url_with_path_and_query() {
        // Path and query params on a public IP are fine
        assert!(
            assert_safe_peer_url("https://93.184.216.34/federation/query?v=1")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_url_with_credentials() {
        // user:pass@ in URL — url::Url parses this but host is still extracted correctly
        // The actual host is still private, so it should be rejected
        assert!(assert_safe_peer_url("https://user:pass@192.168.1.1/")
            .await
            .is_err());
    }

    // ── is_blocked_ip unit tests (internal helper) ────────────────────────────

    #[test]
    fn blocked_ip_loopback_v4() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("127.0.0.2".parse().unwrap()));
        assert!(is_blocked_ip("127.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocked_ip_private_v4_ranges() {
        assert!(is_blocked_ip("10.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("10.255.255.255".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.0".parse().unwrap()));
        assert!(is_blocked_ip("172.31.255.255".parse().unwrap()));
        assert!(is_blocked_ip("192.168.0.0".parse().unwrap()));
        assert!(is_blocked_ip("192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn blocked_ip_cgnat_boundaries() {
        assert!(!is_blocked_ip("100.63.255.255".parse().unwrap())); // just below
        assert!(is_blocked_ip("100.64.0.0".parse().unwrap())); // start
        assert!(is_blocked_ip("100.127.255.255".parse().unwrap())); // end
        assert!(!is_blocked_ip("100.128.0.0".parse().unwrap())); // just above
    }

    #[test]
    fn blocked_ip_link_local_boundaries() {
        assert!(!is_blocked_ip("169.253.255.255".parse().unwrap())); // just below
        assert!(is_blocked_ip("169.254.0.0".parse().unwrap())); // start
        assert!(is_blocked_ip("169.254.255.255".parse().unwrap())); // end
        assert!(!is_blocked_ip("169.255.0.0".parse().unwrap())); // just above
    }

    #[test]
    fn blocked_ip_v4_special() {
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap())); // unspecified
        assert!(is_blocked_ip("255.255.255.255".parse().unwrap())); // broadcast
    }

    #[test]
    fn not_blocked_public_v4() {
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap())); // Cloudflare DNS
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap())); // Google DNS
        assert!(!is_blocked_ip("93.184.216.34".parse().unwrap())); // example.com
        assert!(!is_blocked_ip("11.0.0.0".parse().unwrap())); // just above 10.x
        assert!(!is_blocked_ip("172.32.0.0".parse().unwrap())); // just above 172.31.x
        assert!(!is_blocked_ip("192.169.0.0".parse().unwrap())); // just above 192.168.x
    }

    #[test]
    fn blocked_ip_ipv6_loopback_and_unspecified() {
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("::".parse().unwrap()));
    }

    #[test]
    fn blocked_ip_ipv6_unique_local_boundaries() {
        assert!(is_blocked_ip("fc00::".parse().unwrap())); // start fc00::/7
        assert!(is_blocked_ip(
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        )); // end
        assert!(!is_blocked_ip("fe00::".parse().unwrap())); // just above (not link-local either)
    }

    #[test]
    fn blocked_ip_ipv6_link_local_boundaries() {
        assert!(is_blocked_ip("fe80::".parse().unwrap())); // start fe80::/10
        assert!(is_blocked_ip(
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        )); // end
        assert!(!is_blocked_ip("fec0::".parse().unwrap())); // just above (reserved, not link-local)
    }

    #[test]
    fn blocked_ip_ipv4_mapped() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap())); // loopback
        assert!(is_blocked_ip("::ffff:10.0.0.1".parse().unwrap())); // private
        assert!(is_blocked_ip("::ffff:192.168.1.1".parse().unwrap())); // private
        assert!(is_blocked_ip("::ffff:0.0.0.0".parse().unwrap())); // unspecified
        assert!(!is_blocked_ip("::ffff:1.1.1.1".parse().unwrap())); // public
    }

    #[test]
    fn is_cgnat_boundaries() {
        // 100.64.0.0/10 = octets[0]==100, octets[1] in [64, 127]
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 255, 255))); // just below
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 0))); // start
        assert!(is_cgnat(Ipv4Addr::new(100, 96, 0, 0))); // midpoint
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255))); // end
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 0))); // just above
        assert!(!is_cgnat(Ipv4Addr::new(101, 64, 0, 0))); // different first octet
        assert!(!is_cgnat(Ipv4Addr::new(99, 64, 0, 0))); // different first octet
    }
}
