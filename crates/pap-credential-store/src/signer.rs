//! VaultSigner — a PrincipalSigner backed by an encrypted vault item.
//!
//! Decrypts the principal seed from the vault, constructs a PrincipalKeypair,
//! and implements the PrincipalSigner trait. The seed lives in memory only
//! while the signer exists; the vault can be locked independently.

use ed25519_dalek::{Signer, VerifyingKey};
use pap_did::PrincipalKeypair;
use pap_webauthn::signer::PrincipalSigner;
use pap_webauthn::WebAuthnError;
use zeroize::Zeroizing;

/// A PrincipalSigner constructed from a vault-stored principal seed.
pub struct VaultSigner {
    keypair: PrincipalKeypair,
}

impl VaultSigner {
    /// Construct from a decrypted 32-byte Ed25519 seed.
    ///
    /// The seed should come from `Vault::get_principal_seed()`.
    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Result<Self, WebAuthnError> {
        let keypair = PrincipalKeypair::from_bytes(seed)
            .map_err(|e| WebAuthnError::InvalidCredential(e.to_string()))?;
        Ok(Self { keypair })
    }

    /// Access the underlying keypair for code that needs the concrete type
    /// (e.g. mandate signing, VC issuance).
    pub fn keypair(&self) -> &PrincipalKeypair {
        &self.keypair
    }
}

impl PrincipalSigner for VaultSigner {
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use ed25519_dalek::Verifier;

    use crate::sqlite::SqliteVaultStore;
    use crate::types::VaultItemData;
    use crate::vault::Vault;

    #[test]
    fn vault_signer_sign_verify_roundtrip() {
        // Generate a real keypair, store its seed, reconstruct via VaultSigner
        let original = PrincipalKeypair::generate();
        let seed = original.signing_key().to_bytes();
        let zeroized_seed = Zeroizing::new(seed);

        let signer = VaultSigner::from_seed(&zeroized_seed).unwrap();
        assert_eq!(signer.did(), original.did());

        let message = b"PAP vault signer test";
        let sig_bytes = signer.sign(message).unwrap();
        let signature =
            ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
        signer.verifying_key().verify(message, &signature).unwrap();
    }

    #[test]
    fn vault_signer_from_vault_integration() {
        let store = SqliteVaultStore::in_memory().unwrap();
        let vault = Vault::create_with_fast_kdf(store, "pw").unwrap();

        // Generate seed and store it
        let kp = PrincipalKeypair::generate();
        let seed_bytes = kp.signing_key().to_bytes();
        let seed_b64 = URL_SAFE_NO_PAD.encode(seed_bytes);

        let id = vault
            .add_item(VaultItemData::PrincipalSeed {
                name: "Test Identity".into(),
                seed_b64,
                did: kp.did(),
            })
            .unwrap();

        // Extract seed from vault and build signer
        let seed = vault.get_principal_seed(&id).unwrap();
        let signer = VaultSigner::from_seed(&seed).unwrap();

        // Signer should produce the same DID
        assert_eq!(signer.did(), kp.did());

        // Signatures should be verifiable
        let msg = b"end-to-end vault signer";
        let sig = signer.sign(msg).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(sig.as_slice().try_into().unwrap());
        kp.verifying_key().verify(msg, &signature).unwrap();
    }

    #[test]
    fn vault_signer_is_trait_object_compatible() {
        let kp = PrincipalKeypair::generate();
        let seed = Zeroizing::new(kp.signing_key().to_bytes());
        let signer = VaultSigner::from_seed(&seed).unwrap();

        // Must work as Box<dyn PrincipalSigner>
        let boxed: Box<dyn PrincipalSigner> = Box::new(signer);
        assert!(boxed.did().starts_with("did:key:z"));
        let sig = boxed.sign(b"trait object").unwrap();
        assert_eq!(sig.len(), 64);
    }
}
