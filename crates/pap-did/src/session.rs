use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand::rngs::OsRng;

use crate::principal::public_key_to_did;
use crate::DidError;

/// Ephemeral session keypair — single-use, not linked to any persistent identity.
/// Generated fresh for each session handshake and discarded at session close.
pub struct SessionKeypair {
    signing_key: SigningKey,
}

impl SessionKeypair {
    /// Generate a new ephemeral session keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// The ephemeral session DID (did:key format, same derivation as principal).
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

    /// The Ed25519 signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Sign arbitrary bytes with the ephemeral key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against this session key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), DidError> {
        self.verifying_key()
            .verify(message, signature)
            .map_err(|_| DidError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrincipalKeypair;

    #[test]
    fn session_keys_are_unique() {
        let s1 = SessionKeypair::generate();
        let s2 = SessionKeypair::generate();
        assert_ne!(s1.did(), s2.did());
    }

    #[test]
    fn session_key_unlinked_to_principal() {
        let principal = PrincipalKeypair::generate();
        let session = SessionKeypair::generate();
        assert_ne!(principal.did(), session.did());
    }

    #[test]
    fn session_sign_verify() {
        let sk = SessionKeypair::generate();
        let msg = b"session payload";
        let sig = sk.sign(msg);
        assert!(sk.verify(msg, &sig).is_ok());
        assert!(sk.verify(b"tampered", &sig).is_err());
    }
}
