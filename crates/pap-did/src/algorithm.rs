//! Signature algorithm registry for PAP.
//!
//! PAP v1.0 uses Ed25519 exclusively. This module defines a `SignatureAlgorithm`
//! enum that is `#[non_exhaustive]` so that future versions can add algorithms
//! (e.g., ML-DSA-65 for post-quantum resistance) without a semver-breaking change.

use serde::{Deserialize, Serialize};

/// Identifies the signature algorithm used for a DID key or signable artifact.
///
/// # Adding a new algorithm
///
/// 1. Add a variant to this enum with its multicodec prefix, JWS alg, etc.
/// 2. Implement the `match` arms in every method below.
/// 3. In each signable struct's `sign()`/`verify()`, add a `match` arm for
///    the new algorithm.
/// 4. Update `PrincipalKeypair` (or create a new keypair type) to support
///    the new key type.
///
/// See `docs/algorithm-agility.md` for the full migration checklist.
///
/// # Serde representation
///
/// Serializes as the JWS `alg` string value for wire compatibility:
/// `"EdDSA"` for Ed25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032) — the only algorithm in PAP v1.0.
    #[default]
    #[serde(rename = "EdDSA")]
    Ed25519,
    // Future: ML-DSA-65 (FIPS 204) for post-quantum resistance.
    // MlDsa65,
}

impl SignatureAlgorithm {
    /// Multicodec prefix bytes for this algorithm's public key encoding.
    ///
    /// Used in `did:key` encoding: `did:key:z<base58btc(prefix ++ public_key_bytes)>`.
    /// See <https://github.com/multiformats/multicodec/blob/master/table.csv>.
    pub fn multicodec_prefix(&self) -> &'static [u8] {
        match self {
            Self::Ed25519 => &[0xed, 0x01],
        }
    }

    /// JWS `alg` header value (RFC 7518 / RFC 8037).
    pub fn jws_alg(&self) -> &'static str {
        match self {
            Self::Ed25519 => "EdDSA",
        }
    }

    /// W3C DID verification method type string.
    pub fn verification_key_type(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519VerificationKey2020",
        }
    }

    /// W3C Linked Data proof type string (used in VC proof sections).
    pub fn proof_type(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519Signature2020",
        }
    }

    /// Expected public key size in bytes.
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
        }
    }

    /// Expected signature size in bytes.
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Ed25519 => 64,
        }
    }

    /// Detect algorithm from a multicodec prefix.
    ///
    /// Returns `None` if the prefix is unrecognized.
    pub fn from_multicodec_prefix(prefix: &[u8]) -> Option<Self> {
        if prefix.len() >= 2 && prefix[0] == 0xed && prefix[1] == 0x01 {
            Some(Self::Ed25519)
        } else {
            None
        }
    }

    /// Display name for logging and error messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
        }
    }
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let alg = SignatureAlgorithm::Ed25519;
        let json = serde_json::to_string(&alg).unwrap();
        assert_eq!(json, "\"EdDSA\"");

        let parsed: SignatureAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn default_is_ed25519() {
        assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Ed25519);
    }

    #[test]
    fn multicodec_detection() {
        assert_eq!(
            SignatureAlgorithm::from_multicodec_prefix(&[0xed, 0x01]),
            Some(SignatureAlgorithm::Ed25519)
        );
        assert_eq!(
            SignatureAlgorithm::from_multicodec_prefix(&[0xed, 0x01, 0x00]),
            Some(SignatureAlgorithm::Ed25519)
        );
        assert_eq!(
            SignatureAlgorithm::from_multicodec_prefix(&[0x12, 0x00]),
            None
        );
        assert_eq!(SignatureAlgorithm::from_multicodec_prefix(&[0xed]), None);
        assert_eq!(SignatureAlgorithm::from_multicodec_prefix(&[]), None);
    }

    #[test]
    fn metadata_correctness() {
        let alg = SignatureAlgorithm::Ed25519;
        assert_eq!(alg.multicodec_prefix(), &[0xed, 0x01]);
        assert_eq!(alg.jws_alg(), "EdDSA");
        assert_eq!(alg.verification_key_type(), "Ed25519VerificationKey2020");
        assert_eq!(alg.proof_type(), "Ed25519Signature2020");
        assert_eq!(alg.public_key_size(), 32);
        assert_eq!(alg.signature_size(), 64);
        assert_eq!(alg.as_str(), "Ed25519");
        assert_eq!(alg.to_string(), "Ed25519");
    }
}
