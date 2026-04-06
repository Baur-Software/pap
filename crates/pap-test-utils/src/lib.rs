//! Shared test helpers for the PAP workspace.
//!
//! Provides `make_keypair` and `did_from_key` — previously duplicated in 10
//! locations across `pap-core`, `pap-credential`, `pap-federation`, and `benches`.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// Generate a fresh Ed25519 signing key using the OS CSPRNG.
pub fn make_keypair() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Derive a `did:key` string from an Ed25519 signing key.
///
/// The conversion through `SigningKey::to_bytes()` is always valid, so this
/// uses `expect` with an invariant message rather than propagating an error.
pub fn did_from_key(key: &SigningKey) -> String {
    pap_did::PrincipalKeypair::from_bytes(&key.to_bytes())
        .expect("SigningKey bytes are always valid for PrincipalKeypair")
        .did()
}
