//! Payment proof extensions for mandate scopes (spec section 13.1).
//!
//! A mandate MAY carry a `PaymentProof` — a zero-knowledge commitment
//! proving payment capability without revealing amount or destination.
//! Two proof types are supported:
//!
//! - **Lightning**: SHA-256 of a BOLT-11 invoice payment hash
//! - **Ecash**: SHA-256 of a Cashu blind-signed token
//!
//! Only commitment hashes are stored. No amounts, destinations, mints,
//! or other identifying payment data enters the mandate or receipt.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::PapError;

/// SHA-256 commitment of a BOLT-11 Lightning invoice payment hash.
///
/// The preimage is never stored — only the hash of the payment hash,
/// proving the principal holds a valid Lightning payment without
/// revealing amount, destination, or routing information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bolt11Hash {
    /// Base64url-no-pad encoded SHA-256 hash
    pub hash: String,
}

impl Bolt11Hash {
    /// Create from a raw payment hash (will be SHA-256'd).
    pub fn from_preimage(payment_hash: &[u8]) -> Self {
        let digest = Sha256::digest(payment_hash);
        use base64::Engine;
        Self {
            hash: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        }
    }

    /// Create from an already-computed base64url hash.
    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self { hash: hash.into() }
    }

    /// Verify that a given preimage produces this commitment.
    pub fn verify_preimage(&self, payment_hash: &[u8]) -> bool {
        let digest = Sha256::digest(payment_hash);
        use base64::Engine;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        self.hash == expected
    }
}

/// SHA-256 commitment of a Cashu ecash blind-signed token.
///
/// The token itself is never stored — only its hash, proving the
/// principal holds a valid ecash token without revealing amount,
/// mint, or blinding factors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CashuTokenHash {
    /// Base64url-no-pad encoded SHA-256 hash
    pub hash: String,
}

impl CashuTokenHash {
    /// Create from a raw Cashu token (will be SHA-256'd).
    pub fn from_token(token: &[u8]) -> Self {
        let digest = Sha256::digest(token);
        use base64::Engine;
        Self {
            hash: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
        }
    }

    /// Create from an already-computed base64url hash.
    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self { hash: hash.into() }
    }

    /// Verify that a given token produces this commitment.
    pub fn verify_token(&self, token: &[u8]) -> bool {
        let digest = Sha256::digest(token);
        use base64::Engine;
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        self.hash == expected
    }
}

/// Zero-knowledge payment proof commitment.
///
/// Carried in a mandate's `payment_proof` field. Contains only
/// a cryptographic commitment — no amounts, destinations, or
/// identifying payment data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PaymentProof {
    /// BOLT-11 Lightning invoice payment hash commitment
    Lightning(Bolt11Hash),
    /// Cashu ecash blind-signed token commitment
    Ecash(CashuTokenHash),
}

impl PaymentProof {
    /// Create a Lightning payment proof from a raw payment hash.
    pub fn lightning(payment_hash: &[u8]) -> Self {
        PaymentProof::Lightning(Bolt11Hash::from_preimage(payment_hash))
    }

    /// Create an Ecash payment proof from a raw Cashu token.
    pub fn ecash(token: &[u8]) -> Self {
        PaymentProof::Ecash(CashuTokenHash::from_token(token))
    }

    /// The commitment hash, regardless of proof type.
    pub fn commitment(&self) -> &str {
        match self {
            PaymentProof::Lightning(h) => &h.hash,
            PaymentProof::Ecash(h) => &h.hash,
        }
    }

    /// Verify a preimage/token against this proof's commitment.
    pub fn verify(&self, data: &[u8]) -> bool {
        match self {
            PaymentProof::Lightning(h) => h.verify_preimage(data),
            PaymentProof::Ecash(h) => h.verify_token(data),
        }
    }

    /// Validate the proof's structural integrity (hash is valid base64url).
    pub fn validate(&self) -> Result<(), PapError> {
        use base64::Engine;
        let hash = self.commitment();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(hash)
            .map_err(|e| {
                PapError::PaymentProofError(format!("invalid commitment encoding: {e}"))
            })?;
        if bytes.len() != 32 {
            return Err(PapError::PaymentProofError(format!(
                "commitment must be 32 bytes (SHA-256), got {}",
                bytes.len()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt11_hash_from_preimage_and_verify() {
        let payment_hash = b"test-lightning-payment-hash-0001";
        let bolt11 = Bolt11Hash::from_preimage(payment_hash);

        assert!(bolt11.verify_preimage(payment_hash));
        assert!(!bolt11.verify_preimage(b"wrong-preimage"));
    }

    #[test]
    fn cashu_token_hash_from_token_and_verify() {
        let token = b"cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHA";
        let cashu = CashuTokenHash::from_token(token);

        assert!(cashu.verify_token(token));
        assert!(!cashu.verify_token(b"wrong-token"));
    }

    #[test]
    fn payment_proof_lightning_commitment() {
        let proof = PaymentProof::lightning(b"payment-hash-bytes");
        assert!(!proof.commitment().is_empty());
        assert!(proof.verify(b"payment-hash-bytes"));
        assert!(!proof.verify(b"other-bytes"));
    }

    #[test]
    fn payment_proof_ecash_commitment() {
        let proof = PaymentProof::ecash(b"cashu-token-bytes");
        assert!(!proof.commitment().is_empty());
        assert!(proof.verify(b"cashu-token-bytes"));
        assert!(!proof.verify(b"other-bytes"));
    }

    #[test]
    fn payment_proof_validate_valid() {
        let proof = PaymentProof::lightning(b"some-data");
        assert!(proof.validate().is_ok());
    }

    #[test]
    fn payment_proof_validate_invalid_encoding() {
        let proof = PaymentProof::Lightning(Bolt11Hash {
            hash: "not-valid-base64!!!".into(),
        });
        assert!(proof.validate().is_err());
    }

    #[test]
    fn payment_proof_validate_wrong_length() {
        use base64::Engine;
        let short_hash =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"too-short");
        let proof = PaymentProof::Lightning(Bolt11Hash { hash: short_hash });
        assert!(proof.validate().is_err());
    }

    #[test]
    fn payment_proof_serialization_roundtrip_lightning() {
        let proof = PaymentProof::lightning(b"bolt11-payment-hash");
        let json = serde_json::to_string(&proof).unwrap();
        let proof2: PaymentProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, proof2);

        // Verify tagged format
        assert!(json.contains("\"type\":\"Lightning\""));
    }

    #[test]
    fn payment_proof_serialization_roundtrip_ecash() {
        let proof = PaymentProof::ecash(b"cashu-token");
        let json = serde_json::to_string(&proof).unwrap();
        let proof2: PaymentProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, proof2);

        assert!(json.contains("\"type\":\"Ecash\""));
    }

    #[test]
    fn bolt11_from_hash_direct() {
        use base64::Engine;
        let hash =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"data"));
        let bolt11 = Bolt11Hash::from_hash(&hash);
        assert_eq!(bolt11.hash, hash);
    }

    #[test]
    fn cashu_from_hash_direct() {
        use base64::Engine;
        let hash =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"data"));
        let cashu = CashuTokenHash::from_hash(&hash);
        assert_eq!(cashu.hash, hash);
    }

    #[test]
    fn different_proofs_different_commitments() {
        let lightning = PaymentProof::lightning(b"same-data");
        let ecash = PaymentProof::ecash(b"same-data");
        // Same input data produces the same hash regardless of variant
        assert_eq!(lightning.commitment(), ecash.commitment());
    }
}
