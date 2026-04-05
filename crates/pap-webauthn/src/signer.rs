use ed25519_dalek::VerifyingKey;
use pap_did::SignatureAlgorithm;

use crate::error::WebAuthnError;

/// Abstraction over signing backends for PAP principals.
///
/// Implementations may use software keys (`SoftwareSigner`), WebAuthn
/// hardware authenticators (`MockWebAuthnSigner`), or any future backend.
/// The protocol layer only sees this trait — it never cares how the key
/// is stored or how the user authenticates.
pub trait PrincipalSigner: Send + Sync {
    /// The did:key identifier derived from this signer's public key.
    fn did(&self) -> String;

    /// Sign arbitrary bytes. Returns the signature for this signer's algorithm.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, WebAuthnError>;

    /// The verifying (public) key for signature verification.
    fn verifying_key(&self) -> VerifyingKey;

    /// The signature algorithm used by this signer.
    /// Defaults to Ed25519 for all existing implementations.
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }
}
