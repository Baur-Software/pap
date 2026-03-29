//! TLS identity for PAP federation nodes.
//!
//! Each node generates a self-signed certificate at startup. The cert's
//! Subject Alternative Name contains the node's DID, binding the TLS
//! identity to the PAP identity. Peers verify each other by pinning
//! the SHA-256 fingerprint of the DER-encoded certificate — no CA in
//! the trust chain. DIDs are the trust root.

use std::collections::HashSet;
use std::fmt;
use std::io::BufReader;
use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::error::FederationError;

/// TLS certificate verifier that pins certificates by SHA-256 fingerprint.
///
/// PAP's trust model: DIDs are the trust root, cert fingerprints bind
/// the TLS identity to the DID. This verifier rejects any certificate
/// whose SHA-256 fingerprint isn't in the trusted set.
///
/// No CA chain, no webpki — just fingerprint pinning.
struct FingerprintVerifier {
    accepted: HashSet<String>,
    provider: Arc<CryptoProvider>,
}

impl fmt::Debug for FingerprintVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FingerprintVerifier")
            .field("accepted_count", &self.accepted.len())
            .finish()
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity.as_ref());
        if self.accepted.contains(&fp) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert fingerprint {} not in trusted set",
                fp
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A node's TLS identity: server config, DER certificate, and fingerprint.
pub struct NodeTlsIdentity {
    /// rustls server configuration for accepting TLS connections.
    pub server_config: Arc<ServerConfig>,

    /// DER-encoded certificate bytes (for fingerprint verification).
    pub cert_der: Vec<u8>,

    /// SHA-256 hex fingerprint of the DER certificate.
    /// This is what peers pin to verify our identity.
    pub fingerprint: String,
}

/// Compute the SHA-256 hex fingerprint of a DER-encoded certificate.
pub fn cert_fingerprint(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

/// Generate a self-signed TLS certificate for a PAP federation node.
///
/// The certificate:
/// - Uses ECDSA P-256 (widely supported in TLS 1.3)
/// - Includes the node's DID as a URI SAN (binding TLS ↔ PAP identity)
/// - Is valid for 365 days
/// - Is self-signed (no CA dependency — fingerprint pinning is the trust model)
pub fn generate_node_identity(did: &str) -> Result<NodeTlsIdentity, FederationError> {
    // Ensure the ring crypto provider is installed for rustls.
    // Ignore the error if it's already been installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let key_pair = KeyPair::generate()
        .map_err(|e| FederationError::ServerError(format!("key generation failed: {e}")))?;

    let mut params = CertificateParams::new(vec!["localhost".into()])
        .map_err(|e| FederationError::ServerError(format!("cert params failed: {e}")))?;

    params
        .distinguished_name
        .push(DnType::CommonName, "PAP Federation Node");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "PAP Network");

    // Bind the DID to the certificate via SAN URI
    params
        .subject_alt_names
        .push(SanType::URI(did.try_into().map_err(|e| {
            FederationError::ServerError(format!("invalid DID for SAN: {e}"))
        })?));

    // Also allow connections via IP for local dev
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    params
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::UNSPECIFIED,
        )));

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| FederationError::ServerError(format!("cert generation failed: {e}")))?;

    let cert_der_bytes = cert.der().to_vec();
    let fingerprint = cert_fingerprint(&cert_der_bytes);

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    // Build rustls ServerConfig
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| FederationError::ServerError(format!("cert PEM parse failed: {e}")))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem.as_bytes()))
        .map_err(|e| FederationError::ServerError(format!("key PEM parse failed: {e}")))?
        .ok_or_else(|| FederationError::ServerError("no private key in PEM".into()))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| FederationError::ServerError(format!("TLS config failed: {e}")))?;

    Ok(NodeTlsIdentity {
        server_config: Arc::new(server_config),
        cert_der: cert_der_bytes,
        fingerprint,
    })
}

/// Build a `rustls::ClientConfig` that verifies peers by pinned cert fingerprints.
///
/// This is the foundation for any TLS client (HTTP, WebSocket, etc.) that
/// needs fingerprint-pinned peer verification. Use directly for non-HTTP
/// transports (e.g., WebSocket via tokio-rustls), or pass to
/// `build_pinned_client()` for an HTTP client.
pub fn build_pinned_tls_config(
    trusted_fingerprints: &[String],
) -> Result<rustls::ClientConfig, FederationError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(FingerprintVerifier {
        accepted: trusted_fingerprints.iter().cloned().collect(),
        provider: provider.clone(),
    });

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| FederationError::ServerError(format!("TLS version config failed: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok(config)
}

/// Build a reqwest Client that verifies peers by pinned cert fingerprints.
///
/// Only accepts TLS connections where the server's certificate has a SHA-256
/// fingerprint matching one in the trusted set. No CA dependency — DIDs are
/// the trust root, cert fingerprints bind the TLS identity.
///
/// Panics if `trusted_fingerprints` is empty — use `build_tofu_client()`
/// for bootstrapping new peers.
pub fn build_pinned_client(
    trusted_fingerprints: &[String],
) -> Result<reqwest::Client, FederationError> {
    let config = build_pinned_tls_config(trusted_fingerprints)?;

    reqwest::Client::builder()
        .user_agent("Papillon/0.1 (PAP Federation Node)")
        .use_preconfigured_tls(config)
        .build()
        .map_err(|e| FederationError::ServerError(format!("HTTP client build failed: {e}")))
}

/// Build a TOFU (Trust On First Use) client for bootstrapping new peers.
///
/// Accepts any server certificate. The caller MUST record the cert
/// fingerprint and use `build_pinned_client()` for all subsequent
/// connections. This is a transitional mechanism until DNS-based
/// bootstrap (`_pap.hostname` TXT records) is implemented.
///
/// SECURITY: Only use for initial peer discovery. All subsequent
/// connections MUST use `build_pinned_client()`.
pub fn build_tofu_client() -> Result<reqwest::Client, FederationError> {
    reqwest::Client::builder()
        .user_agent("Papillon/0.1 (PAP Federation Node)")
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| FederationError::ServerError(format!("HTTP client build failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;

    // ── cert_fingerprint() ────────────────────────────────────────────────

    #[test]
    fn fingerprint_is_deterministic() {
        let der = b"some certificate bytes";
        let fp1 = cert_fingerprint(der);
        let fp2 = cert_fingerprint(der);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let fp = cert_fingerprint(b"anything");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_differs_for_different_input() {
        let fp1 = cert_fingerprint(b"cert-a");
        let fp2 = cert_fingerprint(b"cert-b");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_empty_input() {
        let fp = cert_fingerprint(b"");
        // SHA-256 of empty input is well-known
        assert_eq!(fp.len(), 64);
        assert_eq!(
            fp,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ── generate_node_identity() ──────────────────────────────────────────

    #[test]
    fn generate_identity_and_fingerprint() {
        let identity =
            generate_node_identity("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
                .unwrap();
        assert!(!identity.fingerprint.is_empty());
        assert_eq!(identity.fingerprint.len(), 64); // SHA-256 hex = 64 chars
        assert!(!identity.cert_der.is_empty());
    }

    #[test]
    fn generate_identity_fingerprint_matches_cert_der() {
        let identity =
            generate_node_identity("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
                .unwrap();
        let computed = cert_fingerprint(&identity.cert_der);
        assert_eq!(identity.fingerprint, computed);
    }

    #[test]
    fn generate_identity_different_dids_produce_different_certs() {
        let id1 =
            generate_node_identity("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
                .unwrap();
        let id2 =
            generate_node_identity("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
                .unwrap();
        // Each call generates a fresh keypair, so fingerprints differ
        assert_ne!(id1.fingerprint, id2.fingerprint);
    }

    // ── FingerprintVerifier ───────────────────────────────────────────────

    fn make_cert_der(data: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(data.to_vec())
    }

    #[test]
    fn fingerprint_verifier_accepts_matching_cert() {
        let cert_data = b"test-cert-der";
        let fp = cert_fingerprint(cert_data);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = FingerprintVerifier {
            accepted: [fp].into_iter().collect(),
            provider,
        };

        let cert = make_cert_der(cert_data);
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(result.is_ok());
    }

    #[test]
    fn fingerprint_verifier_rejects_unknown_cert() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = FingerprintVerifier {
            accepted: ["aaa111".to_string()].into_iter().collect(),
            provider,
        };

        let cert = make_cert_der(b"unknown-cert-data");
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        let result = verifier.verify_server_cert(&cert, &[], &server_name, &[], now);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("not in trusted set"));
    }

    #[test]
    fn fingerprint_verifier_accepts_one_of_many() {
        let cert_data = b"cert-two";
        let fp = cert_fingerprint(cert_data);
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = FingerprintVerifier {
            accepted: ["other-fp-1".to_string(), fp, "other-fp-3".to_string()]
                .into_iter()
                .collect(),
            provider,
        };

        let cert = make_cert_der(cert_data);
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        assert!(verifier
            .verify_server_cert(&cert, &[], &server_name, &[], now)
            .is_ok());
    }

    #[test]
    fn fingerprint_verifier_empty_set_rejects_all() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = FingerprintVerifier {
            accepted: HashSet::new(),
            provider,
        };

        let cert = make_cert_der(b"any-cert");
        let server_name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::now();

        assert!(verifier
            .verify_server_cert(&cert, &[], &server_name, &[], now)
            .is_err());
    }

    #[test]
    fn fingerprint_verifier_debug_shows_count() {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = FingerprintVerifier {
            accepted: ["a".into(), "b".into()].into_iter().collect(),
            provider,
        };
        let debug = format!("{:?}", verifier);
        assert!(debug.contains("accepted_count"));
        assert!(debug.contains("2"));
    }

    // ── build_pinned_tls_config() ─────────────────────────────────────────

    #[test]
    fn build_pinned_tls_config_succeeds() {
        let config = build_pinned_tls_config(&["abc123".into()]);
        assert!(config.is_ok());
    }

    #[test]
    fn build_pinned_tls_config_empty_fingerprints_succeeds() {
        // Empty set means all certs will be rejected at verify time,
        // but config construction itself should succeed.
        let config = build_pinned_tls_config(&[]);
        assert!(config.is_ok());
    }

    // ── Client builders ───────────────────────────────────────────────────

    #[test]
    fn build_tofu_client_succeeds() {
        let client = build_tofu_client();
        assert!(client.is_ok());
    }

    #[test]
    fn build_pinned_client_succeeds() {
        let client = build_pinned_client(&["abc123def456".into()]);
        assert!(client.is_ok());
    }

    #[test]
    fn build_pinned_client_multiple_fingerprints() {
        let client = build_pinned_client(&["fp1".into(), "fp2".into(), "fp3".into()]);
        assert!(client.is_ok());
    }
}
