use ed25519_dalek::VerifyingKey;

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

    /// Sign arbitrary bytes. Returns a 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, WebAuthnError>;

    /// The Ed25519 verifying (public) key for signature verification.
    fn verifying_key(&self) -> VerifyingKey;
}
