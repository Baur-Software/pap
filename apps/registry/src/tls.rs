//! TLS certificate fingerprint pinning for outgoing peer connections.
//!
//! Federation peers that use self-signed TLS certificates must supply a
//! SHA-256 fingerprint when they are registered. The [`PinnedCertVerifier`]
//! rustls verifier accepts the certificate only when the fingerprint matches,
//! while still requiring the peer to prove ownership of the private key via
//! the standard TLS handshake signature.
//!
//! Peers with CA-signed certificates need no fingerprint; they are validated
//! by the system root store in the normal way.

use constant_time_eq::constant_time_eq;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

/// Normalise a fingerprint string for comparison: strip non-hex characters
/// (colons, spaces) and lowercase everything so `"AA:BB:CC"` and `"aabbcc"`
/// compare equal.
fn normalise(fp: &str) -> String {
    fp.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// A rustls `ServerCertVerifier` that pins a peer's TLS certificate by its
/// SHA-256 fingerprint of the DER-encoded end-entity certificate.
///
/// - The CA chain is **not** validated — self-signed certs are fine.
/// - The TLS handshake signature **is** validated using the ring provider,
///   so the peer must hold the matching private key.
#[derive(Debug)]
pub(crate) struct PinnedCertVerifier {
    normalised_fp: String,
}

impl PinnedCertVerifier {
    pub(crate) fn new(fingerprint: &str) -> Self {
        Self {
            normalised_fp: normalise(fingerprint),
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let actual = normalise(&hex::encode(Sha256::digest(end_entity.as_ref())));
        if constant_time_eq(actual.as_bytes(), self.normalised_fp.as_bytes()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General(format!(
                "TLS certificate fingerprint mismatch: expected {}, got {}",
                self.normalised_fp, actual
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Enumerate all schemes that ring supports for TLS 1.2 and 1.3.
        use SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA1,
            ECDSA_SHA1_Legacy,
            RSA_PKCS1_SHA256,
            ECDSA_NISTP256_SHA256,
            RSA_PKCS1_SHA384,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

/// Build an outgoing [`reqwest::Client`] for a federation peer.
///
/// - `fingerprint = Some(fp)` → custom rustls verifier that pins the
///   certificate by its SHA-256 fingerprint.  The peer must still prove
///   it holds the private key via the TLS handshake signature.
/// - `fingerprint = None` → standard TLS with system root CAs.
///   Peers using self-signed certificates must have a fingerprint stored
///   or this will fail; peers with CA-signed certs work without one.
pub(crate) fn build_peer_client(
    fingerprint: Option<&str>,
) -> Result<reqwest::Client, reqwest::Error> {
    let timeout = Duration::from_secs(30);

    if let Some(fp) = fingerprint {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(PinnedCertVerifier::new(fp));
        let tls_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports all default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(timeout)
            .build()
    } else {
        reqwest::Client::builder().timeout(timeout).build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    // ── normalise() ───────────────────────────────────────────────────────

    #[test]
    fn normalise_strips_colons() {
        assert_eq!(normalise("AA:BB:CC"), "aabbcc");
    }

    #[test]
    fn normalise_strips_spaces() {
        assert_eq!(normalise("AA BB CC"), "aabbcc");
    }

    #[test]
    fn normalise_lowercases() {
        assert_eq!(normalise("DEADBEEF"), "deadbeef");
    }

    #[test]
    fn normalise_mixed_separators() {
        assert_eq!(normalise("DE:AD BE:EF"), "deadbeef");
    }

    #[test]
    fn normalise_already_normalised() {
        assert_eq!(normalise("aabb0011"), "aabb0011");
    }

    #[test]
    fn normalise_empty_string() {
        assert_eq!(normalise(""), "");
    }

    #[test]
    fn normalise_only_separators() {
        assert_eq!(normalise(":: ::"), "");
    }

    #[test]
    fn normalise_equivalence() {
        // These should all normalise to the same string.
        let a = normalise("AA:BB:CC:DD");
        let b = normalise("aabbccdd");
        let c = normalise("Aa Bb Cc Dd");
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    // ── PinnedCertVerifier ────────────────────────────────────────────────

    fn make_cert_der(data: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(data.to_vec())
    }

    fn fingerprint_of(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[test]
    fn verifier_accepts_matching_fingerprint() {
        let cert_bytes = b"test-certificate-bytes";
        let fp = fingerprint_of(cert_bytes);
        let verifier = PinnedCertVerifier::new(&fp);

        let cert = make_cert_der(cert_bytes);
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn verifier_accepts_uppercase_fingerprint() {
        let cert_bytes = b"test-certificate-bytes";
        let fp = fingerprint_of(cert_bytes).to_uppercase();
        let verifier = PinnedCertVerifier::new(&fp);

        let cert = make_cert_der(cert_bytes);
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn verifier_accepts_colon_separated_fingerprint() {
        let cert_bytes = b"test-certificate-bytes";
        let raw_fp = fingerprint_of(cert_bytes);
        // Insert colons every 2 chars: "aa:bb:cc:..."
        let colon_fp: String = raw_fp
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let verifier = PinnedCertVerifier::new(&colon_fp);

        let cert = make_cert_der(cert_bytes);
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn verifier_rejects_mismatched_fingerprint() {
        let verifier = PinnedCertVerifier::new(
            "0000000000000000000000000000000000000000000000000000000000000000",
        );

        let cert = make_cert_der(b"some-cert-data");
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("fingerprint mismatch"));
    }

    #[test]
    fn verifier_supported_schemes_includes_ed25519() {
        let verifier = PinnedCertVerifier::new("deadbeef");
        let schemes = verifier.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::ED25519));
    }

    #[test]
    fn verifier_supported_schemes_includes_ecdsa_p256() {
        let verifier = PinnedCertVerifier::new("deadbeef");
        let schemes = verifier.supported_verify_schemes();
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    // ── build_peer_client() ───────────────────────────────────────────────

    #[test]
    fn build_peer_client_with_fingerprint_succeeds() {
        let client = build_peer_client(Some("aabbccdd"));
        assert!(client.is_ok());
    }

    #[test]
    fn build_peer_client_without_fingerprint_succeeds() {
        let client = build_peer_client(None);
        assert!(client.is_ok());
    }
}
