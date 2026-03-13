use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
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
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), DidError> {
        self.verifying_key()
            .verify(message, signature)
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
}
