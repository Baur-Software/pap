use ed25519_dalek::{Signer, VerifyingKey};
use pap_did::PrincipalKeypair;

use crate::error::WebAuthnError;
use crate::signer::PrincipalSigner;

/// Wraps an existing `PrincipalKeypair` as a `PrincipalSigner`.
///
/// This is the simplest backend — a software Ed25519 key stored in memory.
/// It exists so that all existing PAP code can adopt the signer trait
/// without changing anything about key generation or storage.
pub struct SoftwareSigner {
    keypair: PrincipalKeypair,
}

impl SoftwareSigner {
    pub fn generate() -> Self {
        Self {
            keypair: PrincipalKeypair::generate(),
        }
    }

    pub fn from_keypair(keypair: PrincipalKeypair) -> Self {
        Self { keypair }
    }

    /// Access the underlying `PrincipalKeypair` for code that still
    /// needs the concrete type (e.g. passing `signing_key()` to
    /// mandate/VC sign methods).
    pub fn keypair(&self) -> &PrincipalKeypair {
        &self.keypair
    }
}

impl PrincipalSigner for SoftwareSigner {
    fn did(&self) -> String {
        self.keypair.did()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, WebAuthnError> {
        let sig = self.keypair.signing_key().sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.keypair.verifying_key()
    }
}
