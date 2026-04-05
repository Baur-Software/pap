use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::DidError;

/// Root keypair bound to the human principal's device.
/// In production this would be backed by WebAuthn / platform authenticator.
/// For the PoC we generate Ed25519 in software.
pub struct PrincipalKeypair {
    signing_key: SigningKey,
}

impl PrincipalKeypair {
    /// Generate a new principal keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstruct from raw secret key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, DidError> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }

    /// The `did:key` identifier derived from this keypair.
    /// Format: did:key:z<base58btc(0xed01 ++ public_key_bytes)>
    pub fn did(&self) -> String {
        public_key_to_did(&self.verifying_key())
    }

    /// The raw public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }

    /// The Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// The Ed25519 signing key (for mandate/token signing).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Sign arbitrary bytes.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against this keypair's public key.
    /// Uses strict verification: rejects small-order public keys and R
    /// components, preventing signature malleability and weak-key forgery.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), DidError> {
        self.verifying_key()
            .verify_strict(message, signature)
            .map_err(|_| DidError::VerificationFailed)
    }
}

/// Convert an Ed25519 public key to a `did:key` identifier.
/// Multicodec prefix for Ed25519 public key: 0xed01
pub fn public_key_to_did(key: &VerifyingKey) -> String {
    let mut prefixed = Vec::with_capacity(34);
    prefixed.push(0xed);
    prefixed.push(0x01);
    prefixed.extend_from_slice(&key.to_bytes());
    let encoded = bs58::encode(&prefixed).into_string();
    format!("did:key:z{encoded}")
}

/// Extract public key bytes from a `did:key` identifier.
pub fn did_to_public_key_bytes(did: &str) -> Result<[u8; 32], DidError> {
    let z_part = did
        .strip_prefix("did:key:z")
        .ok_or_else(|| DidError::InvalidDid(did.to_string()))?;
    let decoded = bs58::decode(z_part)
        .into_vec()
        .map_err(|e| DidError::InvalidDid(e.to_string()))?;
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(DidError::InvalidDid("invalid multicodec prefix".into()));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded[2..]);
    Ok(bytes)
}

/// Extract a VerifyingKey from a `did:key` identifier.
/// This is used to verify signatures on artifacts signed by the DID holder.
pub fn verify_key_from_did(did: &str) -> Result<VerifyingKey, DidError> {
    let bytes = did_to_public_key_bytes(did)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| DidError::InvalidDid("invalid public key bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify() {
        let kp = PrincipalKeypair::generate();
        let msg = b"hello principal";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig).is_ok());
    }

    #[test]
    fn did_key_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let did = kp.did();
        assert!(did.starts_with("did:key:z"));

        let bytes = did_to_public_key_bytes(&did).unwrap();
        assert_eq!(bytes, kp.public_key_bytes());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let kp = PrincipalKeypair::generate();
        let secret = kp.signing_key.to_bytes();
        let kp2 = PrincipalKeypair::from_bytes(&secret).unwrap();
        assert_eq!(kp.did(), kp2.did());
    }

    #[test]
    fn wrong_message_fails_verify() {
        let kp = PrincipalKeypair::generate();
        let sig = kp.sign(b"correct message");
        assert!(kp.verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn all_zero_seed_valid_keypair() {
        // Ed25519 accepts any 32 bytes as a valid seed (validity by construction).
        // Verifies PAP's wrapper does not add unnecessary rejection.
        let kp = PrincipalKeypair::from_bytes(&[0u8; 32]).unwrap();
        let sig = kp.sign(b"test");
        assert!(kp.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn all_ones_seed_valid_keypair() {
        // Edge of scalar space — same rationale.
        let kp = PrincipalKeypair::from_bytes(&[0xff; 32]).unwrap();
        let sig = kp.sign(b"test");
        assert!(kp.verify(b"test", &sig).is_ok());
    }

    #[test]
    fn deterministic_signatures() {
        let kp = PrincipalKeypair::from_bytes(&[42u8; 32]).unwrap();
        let sig1 = kp.sign(b"determinism");
        let sig2 = kp.sign(b"determinism");
        assert_eq!(
            sig1.to_bytes(),
            sig2.to_bytes(),
            "Ed25519 is deterministic — same seed + message must produce identical signatures"
        );
    }

    #[test]
    fn did_key_empty_string() {
        assert!(did_to_public_key_bytes("").is_err());
    }

    #[test]
    fn did_key_wrong_prefix() {
        assert!(did_to_public_key_bytes("did:key:Q123").is_err());
    }

    #[test]
    fn did_key_short_payload() {
        assert!(did_to_public_key_bytes("did:key:z11").is_err());
    }

    #[test]
    fn did_key_wrong_multicodec() {
        let kp = PrincipalKeypair::generate();
        let mut wrong_prefix = Vec::with_capacity(34);
        wrong_prefix.push(0xec); // wrong!
        wrong_prefix.push(0x01);
        wrong_prefix.extend_from_slice(&kp.public_key_bytes());
        let encoded = bs58::encode(&wrong_prefix).into_string();
        let did = format!("did:key:z{encoded}");
        assert!(did_to_public_key_bytes(&did).is_err());
    }

    #[test]
    fn did_key_not_on_curve() {
        // y=2 is not on the Ed25519 curve. VerifyingKey::from_bytes performs
        // curve decompression which rejects points not on the curve.
        let mut not_on_curve = Vec::with_capacity(34);
        not_on_curve.push(0xed);
        not_on_curve.push(0x01);
        let mut bad_point = [0u8; 32];
        bad_point[0] = 2; // y=2 in little-endian
        not_on_curve.extend_from_slice(&bad_point);
        let encoded = bs58::encode(&not_on_curve).into_string();
        let did = format!("did:key:z{encoded}");
        assert!(
            verify_key_from_did(&did).is_err(),
            "DID encoding a point not on the curve must be rejected"
        );
    }

    #[test]
    fn did_key_identity_point_accepted() {
        // The identity element (0, 1) IS on the Ed25519 curve and passes
        // VerifyingKey::from_bytes — ed25519-dalek 2.x does NOT perform a
        // prime-order subgroup check at construction time. The subgroup check
        // only happens in verify_strict(), not verify() or from_bytes.
        // This test documents current behavior. See follow-up: verify() vs
        // verify_strict() evaluation for PAP's security boundary.
        let mut identity = Vec::with_capacity(34);
        identity.push(0xed);
        identity.push(0x01);
        let mut identity_y = [0u8; 32];
        identity_y[0] = 0x01; // y = 1 in little-endian (identity element)
        identity.extend_from_slice(&identity_y);
        let encoded = bs58::encode(&identity).into_string();
        let did = format!("did:key:z{encoded}");
        // Documents that verify_key_from_did ACCEPTS the identity element.
        // This is the verify() vs verify_strict() gap — tracked as follow-up.
        assert!(
            verify_key_from_did(&did).is_ok(),
            "identity element is accepted by from_bytes (no subgroup check)"
        );
    }
}
